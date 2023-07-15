// Sample usage of driving an instance of RemedyBG using named pipes.
//
// To use: first, start an named instance of RemedyBG using the "--servername"
// switch.
//
//    remedybg.exe --servername {name}
//
// After RemedyBG is started, this sample can be run to control and make queries
// to the running instance.
//
//    driver {name}
//
// The sample code demonstrates the usage of both these pipes and is written
// using non-overlapped IO for simplicity. Depending on your application, using
// non-blocking IO may be preferable.

#include <stdio.h>
#include <stdbool.h>
#include <windows.h>

#include "remedybg_driver.h"

#define COMMAND_BUF_SIZE 8192
#define REPLY_BUF_SIZE 8192
#define ERROR_MSG_LEN 512

#define fatalf(...) { fprintf(stderr, __VA_ARGS__); exit(1); }

enum PipeType
{
   DebugControlPipe,
   DebugEventsPipe
};

struct Buffer
{
   uint8_t* data;
   uint8_t* curr;
   uint32_t capacity;

   bool err; // true if overflow (read or write) on the buffer
};

static void ReinitBuffer(struct Buffer* buf)
{
   buf->curr = buf->data;
   buf->err = false;
}

struct ClientContext
{
   HANDLE command_pipe_handle;

   struct Buffer cmd;
   struct Buffer reply;

   // Stateful behavior so we don't have to pass these to every command that
   // needs them.
   enum rdbg_DebuggingTargetBehavior dbg_target_behavior;
   enum rdbg_ModifiedSessionBehavior mod_session_behavior;

   char last_error[ERROR_MSG_LEN];
};

static void WriteError(int err_msg_len, char* err_msg, char* format, ...)
{
   va_list args;
   va_start(args, format);

   int n = vsnprintf(err_msg, err_msg_len, format, args);
   if (n > 0)
   {
      FormatMessageA(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL, GetLastError(), 0, err_msg + n,
            err_msg_len - n, 0);
   }

   va_end(args);
}

static bool ContextHadError(struct ClientContext* ctx)
{
   return ctx->last_error[0] != 0 || ctx->cmd.err || ctx->reply.err;
}

//
// Utilities for working with a ClientContext buffers
//
#define SetErrIfOverwrite(buf, sz) \
   (buf)->err = (buf)->err || ((buf)->curr > ((buf)->data + (buf)->capacity) - sz)

#define PushBuffer(buf, ty, val) \
   SetErrIfOverwrite(buf, sizeof(ty)); \
   if (!(buf)->err) { *(ty*)((buf)->curr) = (val); (buf)->curr += sizeof(ty); }

#define PushCommand(buf, cmd) PushBuffer(buf, uint16_t, (uint16_t)(cmd))
#define PushDebuggingTargetBehavior(buf, dtb) \
   PushBuffer(buf, uint8_t, (uint8_t)dtb)
#define PushModifiedSessionBehavior(buf, msb) \
   PushBuffer(buf, uint8_t, (uint8_t)msb)
#define PushBool(buf, val) PushBuffer(buf, uint8_t, (uint8_t)(val))
#define PushId(buf, val) PushBuffer(buf, rdbg_Id, (rdbg_Id)(val))
#define PushU8(buf, val) PushBuffer(buf, uint8_t, (uint8_t)(val))
#define PushU32(buf, val) PushBuffer(buf, uint32_t, (uint32_t)(val))
#define PushS32(buf, val) PushBuffer(buf, int32_t, (int32_t)(val))
#define PushU64(buf, val) PushBuffer(buf, uint64_t, (uint64_t)(val))
#define PushProcessorBreakpointAccessKind(buf, akind) \
   PushBuffer(buf, uint8_t, (uint8_t)akind)

static void PushStringZ(struct Buffer* b, char* str)
{
   uint16_t len = str ? (uint16_t)strlen(str) : 0;
   PushBuffer(b, uint16_t, len);
   SetErrIfOverwrite(b, len);
   if (!b->err && len > 0)
   {
      memcpy(b->curr, str, len);
      b->curr += len;
   }
}

#define PopBuffer(buf, ty) ( \
  (buf)->err = (buf)->err || \
    ((buf)->curr > ((buf)->data + (buf)->capacity) - sizeof(ty)), \
  (buf)->curr += ((buf)->err == 0 ? sizeof(ty) : 0), \
  (buf)->err == 0 ? *(ty*)((buf)->curr - sizeof(ty)) : (ty)0 )

#define PopBool(buf) (rdbg_Bool)PopBuffer(buf, uint8_t)
#define PopU8(buf) PopBuffer(buf, uint8_t)
#define PopU16(buf) PopBuffer(buf, uint16_t)
#define PopU32(buf) PopBuffer(buf, uint32_t)
#define PopS32(buf) PopBuffer(buf, int32_t)
#define PopU64(buf) PopBuffer(buf, uint64_t)
#define PopId(buf) (rdbg_Id)PopU32(buf)
#define PopCommandResult(buf) (enum rdbg_CommandResult)PopBuffer(buf, uint16_t)
#define PopTargetState(buf) (enum rdbg_TargetState)PopBuffer(buf, uint16_t)
#define PopBreakpointKind(buf) (enum rdbg_BreakpointKind)PopBuffer(buf, uint8_t)
#define PopProcessorBreakpointAccessKind(buf) \
   (enum rdbg_ProcessorBreakpointAccessKind)PopBuffer(buf, uint8_t)
#define PopDebugEventKind(buf) (enum rdbg_DebugEventKind)PopBuffer(buf, uint16_t)

static void PopString(struct Buffer* buf, struct rdbg_String** str)
{
   uint16_t len = PopBuffer(buf, uint16_t);
   buf->err = buf->err || buf->curr > buf->data + buf->capacity + len;
   if (!buf->err)
   {
      *str = (struct rdbg_String*)(buf->curr - sizeof(uint16_t));
      buf->curr += len;
   }
   else
   {
      *str = 0;
   }
}

#define PIPE_NAME_PREFIX "\\\\.\\pipe\\"
#define PIPE_NAME_PREFIX_LEN 9

bool InitConnection(char* server_name, enum PipeType pipe_type,
      int last_error_len, char* last_error, HANDLE* ret_pipe_handle)
{
   bool result = false;

   unsigned len = (unsigned)strlen(server_name);
   if (len <= RDBG_MAX_SERVERNAME_LEN)
   {
      char pipe_name[256] = PIPE_NAME_PREFIX;
      strcat(pipe_name, server_name);
      if (pipe_type == DebugEventsPipe)
      {
         strcat(pipe_name, "-events");
      }

      DWORD flags = pipe_type == DebugControlPipe ?
         GENERIC_READ | GENERIC_WRITE :
         GENERIC_READ | FILE_WRITE_ATTRIBUTES;

      HANDLE pipe_handle = CreateFile(pipe_name, flags, 0, NULL, OPEN_EXISTING,
            0, NULL);
      if (pipe_handle != INVALID_HANDLE_VALUE)
      {
         DWORD new_mode = PIPE_READMODE_MESSAGE;
         if (SetNamedPipeHandleState(pipe_handle, &new_mode, NULL, NULL))
         {
            *ret_pipe_handle = pipe_handle;
            result = true;
         }
         else
         {
            WriteError(last_error_len, last_error,
                  "SetNamedPipeHandleState failed: ");
            CloseHandle(pipe_handle);
         }
      }
      else
      {
         WriteError(last_error_len, last_error, "CreateFile failed: ");
      }
   }
   else
   {
      WriteError(last_error_len, last_error, "Server name too long.");
   }

   return result;
}

static void CloseConnection(struct ClientContext* ctx)
{
   CloseHandle(ctx->command_pipe_handle);
}

static void TransactCommand(struct ClientContext* ctx)
{
   DWORD bytes_read = 0;
   BOOL res = 0;
   struct Buffer* reply = &ctx->reply;

   ReinitBuffer(reply);

   if (!ContextHadError(ctx))
   {
      uint8_t* write_ptr = reply->data;

      res = TransactNamedPipe(ctx->command_pipe_handle, ctx->cmd.data,
            (uint32_t)(ctx->cmd.curr - ctx->cmd.data), write_ptr,
            REPLY_BUF_SIZE, &bytes_read, NULL);
      write_ptr += bytes_read;

      while (!res && GetLastError() == ERROR_MORE_DATA)
      {
         int bytes_left = REPLY_BUF_SIZE - (int)(write_ptr - reply->data);
         if (bytes_left > 0)
         {
            res = ReadFile(ctx->command_pipe_handle, write_ptr, bytes_left,
                  &bytes_read, NULL);
            write_ptr += bytes_read;
         }
         else
            break;  // reply buffer full
      }
      if (res)
      {
         reply->capacity = (uint32_t)(write_ptr - reply->data);
      }
      else
      {
         WriteError(sizeof(ctx->last_error), ctx->last_error,
               "TransactCommand failed: ");
      }
   }
}

#define BeginCommand(ctx, c) \
  ReinitBuffer(&((ctx)->cmd)); \
  PushCommand(&((ctx)->cmd), c)

#define SendCommand(ctx, c, res) \
  BeginCommand(ctx, c); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define BeginCommandWithFlags(ctx, c) \
  BeginCommand(ctx, c); \
  PushDebuggingTargetBehavior(&((ctx)->cmd), (ctx)->dbg_target_behavior); \
  PushModifiedSessionBehavior(&((ctx)->cmd), (ctx)->mod_session_behavior)

#define SendCommandWithFlags(ctx, c, res) \
  BeginCommandWithFlags(ctx, c); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define BringDebuggerToForeground(ctx, res) \
  SendCommand(ctx, RDBG_COMMAND_BRING_DEBUGGER_TO_FOREGROUND, res)

#define SetDebuggerWindowPos(ctx, x, y, cx, cy, res) \
  BeginCommand(ctx, RDBG_COMMAND_SET_WINDOW_POS); \
  PushS32(&(ctx)->cmd, x); \
  PushS32(&(ctx)->cmd, y); \
  PushS32(&(ctx)->cmd, cx); \
  PushS32(&(ctx)->cmd, cy); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define GetDebuggerWindowPos(ctx, res, x, y, cx, cy, is_maximized) \
   SendCommand(ctx, RDBG_COMMAND_GET_WINDOW_POS, res); \
   *(x) = PopId(&((ctx)->reply)); \
   *(y) = PopId(&((ctx)->reply)); \
   *(cx) = PopId(&((ctx)->reply)); \
   *(cy) = PopId(&((ctx)->reply)); \
   *(is_maximized) = PopBool(&((ctx)->reply)) != 0

#define ExitDebugger(ctx, res) \
  SendCommandWithFlags(ctx, RDBG_COMMAND_EXIT_DEBUGGER, res)

#define GetIsSessionModified(ctx, res, is_modified) \
   SendCommand(ctx, RDBG_COMMAND_GET_IS_SESSION_MODIFIED, res); \
   *(is_modified) = PopBool(&((ctx)->reply)) != 0

#define GetSessionFilename(ctx, res, filename) \
   SendCommand(ctx, RDBG_COMMAND_GET_SESSION_FILENAME, res); \
   PopString(&((ctx)->reply), filename)

#define NewSession(ctx, res) \
   SendCommandWithFlags(ctx, RDBG_COMMAND_NEW_SESSION, res)

#define SendCommandWithString(ctx, c, str, res) \
  BeginCommand(ctx, c); \
  PushStringZ(&(ctx)->cmd, str); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define OpenSession(ctx, filename, res) \
  SendCommandWithString(ctx, RDBG_COMMAND_OPEN_SESSION, filename, res)

#define SaveSession(ctx, res) \
  SendCommandWithFlags(ctx, RDBG_COMMAND_SAVE_SESSION, res)

#define SaveAsSession(ctx, filename, res) \
  SendCommandWithString(ctx, RDBG_COMMAND_SAVE_AS_SESSION, filename, res)

#define GetSessionConfigs(ctx, res, cfg_it) \
  SendCommand(ctx, RDBG_COMMAND_GET_SESSION_CONFIGS, res); \
  BufIterator_Init(cfg_it, PopBuffer(&((ctx)->reply), uint16_t), \
        ((ctx)->reply))

#define AddSessionConfig(ctx, command, args, wdir, env, inh, brk, res, id) \
  BeginCommand(ctx, RDBG_COMMAND_ADD_SESSION_CONFIG); \
  PushStringZ(&(ctx)->cmd, command); \
  PushStringZ(&(ctx)->cmd, args); \
  PushStringZ(&(ctx)->cmd, wdir); \
  PushStringZ(&(ctx)->cmd, env); \
  PushBool(&(ctx)->cmd, inh); \
  PushBool(&(ctx)->cmd, brk); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  *(id) = PopId(&((ctx)->reply))

#define SendCommandWithId(ctx, c, id, res) \
  BeginCommand(ctx, c); \
  PushId(&(ctx)->cmd, id); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define SetActiveSessionConfig(ctx, id, res) \
  SendCommandWithId(ctx, RDBG_COMMAND_SET_ACTIVE_SESSION_CONFIG, id, res)

#define DeleteSessionConfig(ctx, id, res) \
  SendCommandWithId(ctx, RDBG_COMMAND_DELETE_SESSION_CONFIG, id, res)

#define DeleteAllSessionConfigs(ctx, res) \
  SendCommand(ctx, RDBG_COMMAND_DELETE_ALL_SESSION_CONFIGS, res)

#define GoToFileAtLine(ctx, filename, line, res, id) \
  BeginCommand(ctx, RDBG_COMMAND_GOTO_FILE_AT_LINE); \
  PushStringZ(&(ctx)->cmd, filename); \
  PushBuffer(&(ctx)->cmd, uint32_t, line); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  *(id) = PopId(&((ctx)->reply))

#define CloseFileById(ctx, id, res) \
  SendCommandWithId(ctx, RDBG_COMMAND_CLOSE_FILE, id, res)

#define CloseAllFiles(ctx, res) \
  SendCommand(ctx, RDBG_COMMAND_CLOSE_ALL_FILES, res)

#define GetCurrentFile(ctx, res, file_id, filename, line_num) \
  SendCommand(ctx, RDBG_COMMAND_GET_CURRENT_FILE, res); \
  *(file_id) = PopId(&(ctx)->reply); \
  PopString(&(ctx)->reply, filename); \
  *(line_num) = PopBuffer(&(ctx)->reply, uint32_t)

#define GetOpenFiles(ctx, res, file_it) \
  SendCommand(ctx, RDBG_COMMAND_GET_OPEN_FILES, res); \
  BufIterator_Init(file_it, PopBuffer(&((ctx)->reply), uint16_t), ((ctx)->reply))

#define StartDebugging(ctx, break_at_entry_point, res) \
  BeginCommand(ctx, RDBG_COMMAND_START_DEBUGGING); \
  PushBool(&(ctx)->cmd, break_at_entry_point); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define StopDebugging(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_STOP_DEBUGGING, res)

#define RestartDebugging(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_RESTART_DEBUGGING, res)

#define AttachToProcessById(ctx, pid, cnt, res) \
  BeginCommand(ctx, RDBG_COMMAND_ATTACH_TO_PROCESS_BY_PID); \
  PushBuffer(&(ctx)->cmd, uint32_t, (uint32_t)(pid)); \
  PushBool(&(ctx)->cmd, cnt); \
  PushDebuggingTargetBehavior(&((ctx)->cmd), (ctx)->dbg_target_behavior); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define AttachToProcessByName(ctx, name, cnt, res) \
  BeginCommand(ctx, RDBG_COMMAND_ATTACH_TO_PROCESS_BY_NAME); \
  PushStringZ(&(ctx)->cmd, name); \
  PushBool(&(ctx)->cmd, cnt); \
  PushDebuggingTargetBehavior(&((ctx)->cmd), (ctx)->dbg_target_behavior); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define DetachFromProcess(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_DETACH_FROM_PROCESS, res)

#define StepIntoByLine(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_STEP_INTO_BY_LINE, res)

#define StepIntoByInstruction(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_STEP_INTO_BY_INSTRUCTION, res)

#define StepOverByLine(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_STEP_OVER_BY_LINE, res)

#define StepOverByInstruction(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_STEP_OVER_BY_INSTRUCTION, res)

#define StepOut(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_STEP_OUT, res)

#define ContinueExecution(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_CONTINUE_EXECUTION, res)

#define RunToFileAtLine(ctx, filename, line, res) \
  BeginCommand(ctx, RDBG_COMMAND_RUN_TO_FILE_AT_LINE); \
  PushStringZ(&(ctx)->cmd, filename); \
  PushBuffer(&(ctx)->cmd, uint32_t, line); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define BreakExecution(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_BREAK_EXECUTION, res)

#define GetTargetState(ctx, res, state) \
   SendCommand(ctx, RDBG_COMMAND_GET_TARGET_STATE, res); \
  *(state) = PopTargetState(&((ctx)->reply))

#define GetAllBreakpoints(ctx, res, bp_it) \
  SendCommand(ctx, RDBG_COMMAND_GET_BREAKPOINTS, res); \
  BufIterator_Init(bp_it, PopBuffer(&((ctx)->reply), uint16_t), ((ctx)->reply))

#define GetBreakpoint(ctx, id, res, bp) \
  SendCommandWithId(ctx, RDBG_COMMAND_GET_BREAKPOINT, id, res); \
  PopBreakpoint(&((ctx)->reply), bp)

#define GetBreakpointLocations(ctx, id, res, num_locs) \
  SendCommandWithId(ctx, RDBG_COMMAND_GET_BREAKPOINT_LOCATIONS, id, res); \
  *(num_locs) = PopU16(&((ctx)->reply))

#define GetFunctionOverloads(ctx, res, fn_name, fno_it) \
  BeginCommand(ctx, RDBG_COMMAND_GET_FUNCTION_OVERLOADS); \
  PushStringZ(&(ctx)->cmd, fn_name); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  BufIterator_Init(fno_it, PopU8(&((ctx)->reply)), ((ctx)->reply))

#define AddBreakpointAtFn(ctx, fn_name, oid, cond, res, bp_id) \
  BeginCommand(ctx, RDBG_COMMAND_ADD_BREAKPOINT_AT_FUNCTION); \
  PushStringZ(&(ctx)->cmd, fn_name); \
  PushId(&(ctx)->cmd, oid) \
  PushStringZ(&(ctx)->cmd, cond); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  *(bp_id) = PopId(&((ctx)->reply))

#define AddBreakpointAtFilenameLine(ctx, file, line, cond, res, bp_id) \
  BeginCommand(ctx, RDBG_COMMAND_ADD_BREAKPOINT_AT_FILENAME_LINE); \
  PushStringZ(&(ctx)->cmd, file); \
  PushU32(&(ctx)->cmd, line) \
  PushStringZ(&(ctx)->cmd, cond); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  *(bp_id) = PopId(&((ctx)->reply))

#define AddBreakpointAtAddress(ctx, addr, cond, res, bp_id) \
  BeginCommand(ctx, RDBG_COMMAND_ADD_BREAKPOINT_AT_ADDRESS); \
  PushU64(&(ctx)->cmd, addr) \
  PushStringZ(&(ctx)->cmd, cond); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  *(bp_id) = PopId(&((ctx)->reply))

#define AddProcessorBreakpoint(ctx, addr_expr, nbytes, akind, cond, res, bp_id) \
  BeginCommand(ctx, RDBG_COMMAND_ADD_PROCESSOR_BREAKPOINT); \
  PushStringZ(&(ctx)->cmd, addr_expr); \
  PushU8(&(ctx)->cmd, nbytes); \
  PushProcessorBreakpointAccessKind(&(ctx)->cmd, akind); \
  PushStringZ(&(ctx)->cmd, cond); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  *(bp_id) = PopId(&((ctx)->reply))

#define SetBreakpointCondition(ctx, bp_id, cond, res) \
  BeginCommand(ctx, RDBG_COMMAND_SET_BREAKPOINT_CONDITION); \
  PushId(&(ctx)->cmd, bp_id) \
  PushStringZ(&(ctx)->cmd, cond); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define UpdateBreakpointLine(ctx, bp_id, line, res) \
  BeginCommand(ctx, RDBG_COMMAND_UPDATE_BREAKPOINT_LINE); \
  PushId(&(ctx)->cmd, bp_id); \
  PushU32(&(ctx)->cmd, line); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define EnableBreakpoint(ctx, bp_id, enable, res) \
  BeginCommand(ctx, RDBG_COMMAND_ENABLE_BREAKPOINT); \
  PushId(&(ctx)->cmd, bp_id); \
  PushBool(&(ctx)->cmd, enable); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define DeleteBreakpoint(ctx, bp_id, res) \
  BeginCommand(ctx, RDBG_COMMAND_DELETE_BREAKPOINT); \
  PushId(&(ctx)->cmd, bp_id); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define DeleteAllBreakpoints(ctx, res) \
   SendCommand(ctx, RDBG_COMMAND_DELETE_ALL_BREAKPOINTS, res)

#define GetWatches(ctx, window_num, res, it) \
  BeginCommand(ctx, RDBG_COMMAND_GET_WATCHES); \
  PushU8(&(ctx)->cmd, window_num); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  BufIterator_Init(it, PopU16(&((ctx)->reply)), ((ctx)->reply))

#define AddWatch(ctx, window_num, expr, comment, res, id) \
  BeginCommand(ctx, RDBG_COMMAND_ADD_WATCH); \
  PushU8(&(ctx)->cmd, window_num); \
  PushStringZ(&(ctx)->cmd, expr); \
  PushStringZ(&(ctx)->cmd, comment); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply)); \
  *id = PopId(&((ctx)->reply))

#define UpdateWatchExpression(ctx, id, expr, res) \
  BeginCommand(ctx, RDBG_COMMAND_UPDATE_WATCH_EXPRESSION); \
  PushId(&(ctx)->cmd, id); \
  PushStringZ(&(ctx)->cmd, expr); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define UpdateWatchComment(ctx, id, comment, res) \
  BeginCommand(ctx, RDBG_COMMAND_UPDATE_WATCH_COMMENT); \
  PushId(&(ctx)->cmd, id); \
  PushStringZ(&(ctx)->cmd, comment); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

#define DeleteWatch(ctx, id, res) \
  SendCommandWithId(ctx, RDBG_COMMAND_DELETE_WATCH, id, res)

#define DeleteAllWatches(ctx, window_num, res) \
  BeginCommand(ctx, RDBG_COMMAND_DELETE_ALL_WATCHES); \
  PushU8(&(ctx)->cmd, window_num); \
  TransactCommand((ctx)); \
  *(res) = PopCommandResult(&((ctx)->reply))

struct BufIterator
{
   int n;
   int cur_idx;
   struct Buffer buf;
};

static void BufIterator_Init(struct BufIterator* it, int n,
      struct Buffer b)
{
   it->n = n;
   it->cur_idx = -1;

   // Make a copy of reply buffer so we can make additional calls within loop.
   static uint8_t it_buf[REPLY_BUF_SIZE];
   it->buf.data = it_buf;
   it->buf.curr = it_buf + (b.curr - b.data);
   it->buf.capacity = b.capacity;
   it->buf.err = b.err;
   if (!b.err)
   {
      memcpy(it->buf.data, b.data, b.capacity);
   }
}

struct SessionConfig
{
   rdbg_Id id;
   struct rdbg_String* command;
   struct rdbg_String* command_args;
   struct rdbg_String* working_dir;
   struct rdbg_String* environment_vars;
   rdbg_Bool inherit_environment_vars_from_parent;
   rdbg_Bool break_at_nominal_entry_point;
};

static bool SessionConfigIt_Next(struct BufIterator* it,
      struct SessionConfig* cfg)
{
   bool result = false;
   if (++it->cur_idx < it->n)
   {
      struct Buffer* b = &it->buf;

      cfg->id = PopId(b);
      PopString(b, &cfg->command);
      PopString(b, &cfg->command_args);
      PopString(b, &cfg->working_dir);
      PopString(b, &cfg->environment_vars);
      cfg->inherit_environment_vars_from_parent = PopBool(b);
      cfg->break_at_nominal_entry_point = PopBool(b);

      result = true;
   }
   return result;
}

struct File
{
   rdbg_Id id;
   struct rdbg_String* filename;
   uint32_t line_num;
};

static bool FileIt_Next(struct BufIterator* it, struct File* file)
{
   bool result = false;
   if (++it->cur_idx < it->n)
   {
      struct Buffer* b = &it->buf;

      file->id = PopId(b);
      PopString(b, &file->filename);
      file->line_num = PopBuffer(b, uint32_t);

      result = true;
   }
   return result;
}

struct Breakpoint
{
   rdbg_Id uid;
   rdbg_Bool enabled;
   struct rdbg_String* module_name;
   struct rdbg_String* condition_expr;
   enum rdbg_BreakpointKind kind;
   union
   {
      struct
      {
         struct rdbg_String* function_name;
         rdbg_Id overload_id;
      };
      struct
      {
         struct rdbg_String* filename;
         uint32_t line_num;
      };
      uint64_t address;
      struct
      {
         struct rdbg_String* expression;
         uint8_t num_bytes;
         enum rdbg_InternalProcessorBreakpointType access_kind;
      };
   };
};

struct BreakpointLocation
{
   uint64_t address;
   struct rdbg_String* module_name;
   struct rdbg_String* filename;
   uint32_t actual_line_num;
};

static char* BreakpointKindToString(enum rdbg_BreakpointKind kind)
{
   char* result = "";
   switch (kind)
   {
      case RDBG_BREAKPOINT_KIND_FUNCTION_NAME:
         result = "RDBG_BREAKPOINT_KIND_FUNCTION_NAME";
         break;
      case RDBG_BREAKPOINT_KIND_FILENAME_LINE:
         result = "RDBG_BREAKPOINT_KIND_FILENAME_LINE";
         break;
      case RDBG_BREAKPOINT_KIND_ADDRESS:
         result = "RDBG_BREAKPOINT_KIND_ADDRESS";
         break;
      case RDBG_BREAKPOINT_KIND_PROCESSOR:
         result = "RDBG_BREAKPOINT_KIND_PROCESSOR";
         break;
   }
   return result;
}

char *ProcessorBreakpointAccessKindToString(
      enum rdbg_ProcessorBreakpointAccessKind kind)
{
   char* result = "";
   switch (kind)
   {
      case RDBG_PROCESSOR_BREAKPOINT_ACCESS_KIND_WRITE:
         result = "RDBG_PROCESSOR_BREAKPOINT_ACCESS_KIND_WRITE";
         break;
      case RDBG_PROCESSOR_BREAKPOINT_ACCESS_KIND_READ_WRITE:
         result = "RDBG_PROCESSOR_BREAKPOINT_ACCESS_KIND_READ_WRITE";
         break;
      case RDBG_PROCESSOR_BREAKPOINT_ACCESS_KIND_EXECUTE:
         result = "RDBG_PROCESSOR_BREAKPOINT_ACCESS_KIND_EXECUTE";
         break;
   }
   return result;
}

static void PopBreakpoint(struct Buffer* b, struct Breakpoint* bp)
{
   bp->uid = PopId(b);
   bp->enabled = PopBool(b);
   PopString(b, &bp->module_name);
   PopString(b, &bp->condition_expr);
   bp->kind = PopBreakpointKind(b);
   switch (bp->kind)
   {
      case RDBG_BREAKPOINT_KIND_FUNCTION_NAME:
         PopString(b, &bp->function_name);
         bp->overload_id = PopId(b);
         break;
      case RDBG_BREAKPOINT_KIND_FILENAME_LINE:
         PopString(b, &bp->filename);
         bp->line_num = PopU32(b);
         break;
      case RDBG_BREAKPOINT_KIND_ADDRESS:
         bp->address = PopU64(b);
         break;
      case RDBG_BREAKPOINT_KIND_PROCESSOR:
         PopString(b, &bp->expression);
         bp->num_bytes = PopU8(b);
         bp->access_kind = PopProcessorBreakpointAccessKind(b);
         break;
   }
}

static bool BreakpointIt_Next(struct BufIterator* it, struct Breakpoint* bp)
{
   bool result = false;
   if (++it->cur_idx < it->n)
   {
      PopBreakpoint(&it->buf, bp);
      result = true;
   }
   return result;
}

struct FunctionOverload
{
   rdbg_Id id;
   struct rdbg_String* fn_sig;
};

static bool FunctionOverloadIt_Next(struct BufIterator* it,
      struct FunctionOverload* overload)
{
   bool result = false;
   if (++it->cur_idx < it->n)
   {
      struct Buffer* b = &it->buf;

      overload->id = PopId(b);
      PopString(b, &overload->fn_sig);
      result = true;
   }
   return result;
}

struct Watch
{
   rdbg_Id uid;
   struct rdbg_String* expression;
   struct rdbg_String* comment;
};

static bool WatchExpressionIt_Next(struct BufIterator* it,
      struct Watch* watch)
{
   bool result = false;
   if (++it->cur_idx < it->n)
   {
      struct Buffer* b = &it->buf;

      watch->uid = PopId(b);
      PopString(b, &watch->expression);
      PopString(b, &watch->comment);

      result = true;
   }
   return result;
}

static void MaybePrintField(struct rdbg_String* str, char* field_name)
{
   if (str && str->len)
   {
      fatalf("\t%s: %.*s\n", field_name, str->len,
            (char*)str->data);
   }
}

static char* SourceLocChangedReasonToString(enum rdbg_SourceLocChangedReason reason)
{
   char* result = "";
   switch (reason)
   {
      case RDBG_SOURCE_LOC_CHANGED_REASON_UNSPECIFIED:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_UNSPECIFIED";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_BY_COMMAND_LINE:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_BY_COMMAND_LINE";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_BY_DRIVER:
         result = "RDBG_SOURCE_LOCATION_CHANGED_REASON_BY_DRIVER";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_BREAKPOINT_SELECTED:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_BREAKPOINT_SELECTED";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_CURRENT_FRAME_CHANGED:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_CURRENT_FRAME_CHANGED";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_ACTIVE_THREAD_CHANGED:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_ACTIVE_THREAD_CHANGED";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_BREAKPOINT_HIT:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_BREAKPOINT_HIT";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_EXCEPTION_HIT:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_EXCEPTION_HIT";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_STEP_OVER:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_STEP_OVER";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_STEP_IN:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_STEP_IN";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_STEP_OUT:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_STEP_OUT";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_NON_USER_BREAKPOINT:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_NON_USER_BREAKPOINT";
         break;
      case RDBG_SOURCE_LOC_CHANGED_REASON_DEBUG_BREAK:
         result = "RDBG_SOURCE_LOC_CHANGED_REASON_DEBUG_BREAK";
         break;
   }
   return result;
}

static void WriteDebugEvent(struct Buffer* eb)
{
   struct rdbg_String* str;

   enum rdbg_DebugEventKind kind = PopDebugEventKind(eb);
   switch (kind)
   {
      case RDBG_DEBUG_EVENT_KIND_EXIT_PROCESS:
         fatalf("RDBG_DEBUG_EVENT_KIND_EXIT_PROCESS\n");
         fatalf("\texit_code: %u\n", PopU32(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_TARGET_STARTED:
         fatalf("RDBG_DEBUG_EVENT_KIND_TARGET_STARTED\n");
         fatalf("\tprocess_id: %u\n", PopU32(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_TARGET_ATTACHED:
         fatalf("RDBG_DEBUG_EVENT_KIND_TARGET_ATTACHED\n");
         fatalf("\tprocess_id: %u\n", PopU32(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_TARGET_DETACHED:
         fatalf("RDBG_DEBUG_EVENT_KIND_TARGET_DETACHED\n");
         fatalf("\tprocess_id: %u\n", PopU32(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_TARGET_CONTINUED:
         fatalf("RDBG_DEBUG_EVENT_KIND_TARGET_CONTINUED\n");
         break;
      case RDBG_DEBUG_EVENT_KIND_SOURCE_LOCATION_CHANGED:
         fatalf("RDBG_DEBUG_EVENT_KIND_SOURCE_LOCATION_CHANGED\n");
         PopString(eb, &str);
         if (str && str->len)
         {
            fatalf("\tfilename: %.*s\n", str->len, (char*)str->data);
         }
         fatalf("\tline num: %u\n", PopU32(eb));
         fatalf("\treason: %s\n", SourceLocChangedReasonToString(PopU16(eb)));
         break;
      case RDBG_DEBUG_EVENT_KIND_BREAKPOINT_HIT:
         fatalf("RDBG_DEBUG_EVENT_KIND_BREAKPOINT_HIT\n");
         fatalf("\tuid: %u\n", PopId(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_BREAKPOINT_RESOLVED:
         fatalf("RDBG_DEBUG_EVENT_KIND_BREAKPOINT_RESOLVED\n");
         fatalf("\tuid: %u\n", PopId(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_BREAKPOINT_ADDED:
         fatalf("RDBG_DEBUG_EVENT_KIND_BREAKPOINT_ADDED\n");
         fatalf("\tuid: %u\n", PopId(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_BREAKPOINT_MODIFIED:
         fatalf("RDBG_DEBUG_EVENT_KIND_BREAKPOINT_MODIFIED\n");
         fatalf("\tuid: %u\n", PopId(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_BREAKPOINT_REMOVED:
         fatalf("RDBG_DEBUG_EVENT_KIND_BREAKPOINT_REMOVED\n");
         fatalf("\tuid: %u\n", PopId(eb));
         break;
      case RDBG_DEBUG_EVENT_KIND_OUTPUT_DEBUG_STRING:
         PopString(eb, &str);

         fatalf("RDBG_DEBUG_EVENT_KIND_OUTPUT_DEBUG_STRING\n");
         if (str && str->len)
         {
            fatalf("\tstr: %.*s\n", str->len, (char*)str->data);
         }
         break;

      default:
         fatalf("warning: unknown debug event kind received\n");
   }
}


void DebugControlSample(char* server_name, bool start_debugging)
{
   static uint8_t command_buf[COMMAND_BUF_SIZE];
   static uint8_t reply_buf[REPLY_BUF_SIZE];
   struct ClientContext ctx = {
      .cmd.data = command_buf,
      .cmd.capacity = sizeof(command_buf),
      .reply.data = reply_buf,
      .reply.capacity = sizeof(reply_buf),
      .dbg_target_behavior = RDBG_IF_DEBUGGING_TARGET_STOP_DEBUGGING,
      .mod_session_behavior = RDBG_IF_SESSION_IS_MODIFIED_CONTINUE_WITHOUT_SAVING,
      .last_error[0] = 0,
   };

   if (InitConnection(server_name, DebugControlPipe, sizeof(ctx.last_error),
            ctx.last_error, &ctx.command_pipe_handle))
   {
      enum rdbg_CommandResult res;
			if(start_debugging)
			{
				StartDebugging(&ctx, false, &res);
			}
			else
			{
				StopDebugging(&ctx, &res);
			}
      //StartDebugging(&ctx, false, &res);
      /* Sample calls to each debug control command (commented out).
       *
      enum rdbg_CommandResult res;

      StartDebugging(&ctx, false, &res);
      BringDebuggerToForeground(&ctx, &res);

      SetDebuggerWindowPos(&ctx, 20, 20, 100, 100, &res);

      int x, y, width, height;
      bool is_maximized;
      GetDebuggerWindowPos(&ctx, &res, &x, &y, &width, &height, &is_maximized);
      printf("Window pos: (%d, %d) %d x %d; is maximized: %s\n",
            x, y, width, height, is_maximized ? "true" : "false");

      bool is_modified;
      GetIsSessionModified(&ctx, &res, &is_modified);

      struct rdbg_String* filename;
      GetSessionFilename(&ctx, &res, &filename);
      if (filename && filename->len)
      {
         printf("Session filename: %.*s\n", filename->len, filename->data);
      }

      NewSession(&ctx, &res);
      OpenSession(&ctx, "c:\\path\\to\\session.rdbg", &res);
      SaveSession(&ctx, &res);
      SaveAsSession(&ctx, "c:\\path\\to\\session.rdbg", &res);

      struct BufIterator cfg_it;
      struct SessionConfig cfg;
      GetSessionConfigs(&ctx, &res, &cfg_it);
      while (SessionConfigIt_Next(&cfg_it, &cfg))
      {
         fatalf("Config #%d\n", cfg_it.cur_idx);
         fatalf("\tuid: %hu\n", cfg.id);
         if (cfg.command && cfg.command->len)
         {
            fatalf("\tcommand: %.*s\n", cfg.command->len,
                  (char*)cfg.command->data);
         }
         if (cfg.command_args && cfg.command_args->len)
         {
            fatalf("\tcommand_args: %.*s\n", cfg.command_args->len,
                  (char*)cfg.command_args->data);
         }
         if (cfg.working_dir && cfg.working_dir->len)
         {
            fatalf("\tworking_dir: %.*s\n", cfg.working_dir->len,
                  (char*)cfg.working_dir->data);
         }
         if (cfg.environment_vars && cfg.environment_vars->len)
         {
            fatalf("\tenvironment_vars:\n%.*s\n",
                  cfg.environment_vars->len,
                  (char*)cfg.environment_vars->data);
         }
         fatalf("\tinherit_environment_vars_from_parent: %s\n",
               cfg.inherit_environment_vars_from_parent ? "true" : "false");
         fatalf("\tbreak_at_nominal_entry_point: %s\n",
               cfg.break_at_nominal_entry_point ? "true" : "false");
      }

      rdbg_Id cfg_id;
      AddSessionConfig(&ctx,
            "C:\\windows\\system32\\whoami.exe", "/USER", 0,
            "A=1\nBB=2\nCCC=3", true, true, &res, &cfg_id);
      fatalf("Added session conf (ID: %u).\n", cfg_id);

      SetActiveSessionConfig(&ctx, cfg_id, &res);
      DeleteSessionConfig(&ctx, cfg.id, &res);

      DeleteAllSessionConfigs(&ctx, &res);

      rdbg_Id cur_file_id;
      struct rdbg_String* cur_filename = 0;
      uint32_t line_num;
      GetCurrentFile(&ctx, &res, &cur_file_id, &cur_filename, &line_num);
      if (cur_filename && cur_filename->len)
      {
         fatalf("Topmost file: (%u) %.*s Ln %u\n",
               cur_file_id, cur_filename->len, (char*)cur_filename->data,
               line_num);
      }

      rdbg_Id file_id;
      GoToFileAtLine(&ctx, "C:\\full\\path\\to\\README.txt", 121, &res, &file_id);
      CloseFileById(&ctx, file_id, &res);
      CloseAllFiles(&ctx, &res);

      struct BufIterator file_it;
      struct File file;
      GetOpenFiles(&ctx, &res, &file_it);
      while (FileIt_Next(&file_it, &file))
      {
         fatalf("File #%d\n", file_it.cur_idx);
         fatalf("\tId: %u\n", file.id);
         if (file.filename && file.filename->len)
         {
            fatalf("\tfilename: %.*s\n", file.filename->len,
                  (char*)file.filename->data);
         }
         fatalf("\tLn: %u\n", file.line_num);
      }

      StopDebugging(&ctx, &res);
      RestartDebugging(&ctx, &res);
      AttachToProcessById(&ctx, 14368, true, &res);
      NewSession(&ctx, &res);
      AttachToProcessByName(&ctx, "Calculator.exe", true, &res);
      DetachFromProcess(&ctx, &res);
      StepIntoByLine(&ctx, &res);
      StepIntoByInstruction(&ctx, &res);
      StepOverByLine(&ctx, &res);
      StepOverByInstruction(&ctx, &res);
      StepOut(&ctx, &res);
      ContinueExecution(&ctx, &res);
      RunToFileAtLine(&ctx, "C:\\full\\path\\to\\test.cpp", 13, &res);
      ContinueExecution(&ctx, &res);
      BreakExecution(&ctx, &res);

      enum rdbg_TargetState state;
      GetTargetState(&ctx, &res, &state);
      fatalf("target state: %hu\n", state);

      struct BufIterator bp_it;
      struct Breakpoint bp;
      GetAllBreakpoints(&ctx, &res, &bp_it);
      int idx = 0;
      while (BreakpointIt_Next(&bp_it, &bp))
      {
         fatalf("Breakpoint # %d\n", ++idx);
         fatalf("\tUID: %u\n", bp.uid);
         fatalf("\tEnabled: %s\n", bp.enabled ? "true" : "false");
         MaybePrintField(bp.module_name, "Module");
         MaybePrintField(bp.condition_expr, "Condition");
         fatalf("\tKind: %s\n", BreakpointKindToString(bp.kind));
         switch (bp.kind)
         {
            case RDBG_BREAKPOINT_KIND_FUNCTION_NAME:
               MaybePrintField(bp.function_name, "Function");
               fatalf("\tOverload: %u\n", bp.overload_id);
               break;
            case RDBG_BREAKPOINT_KIND_FILENAME_LINE:
               MaybePrintField(bp.filename, "Filename");
               fatalf("\tLine: %u\n", bp.line_num);
               break;
            case RDBG_BREAKPOINT_KIND_ADDRESS:
               fatalf("\tAddress: 0x%llx\n", bp.address);
               break;
            case RDBG_BREAKPOINT_KIND_PROCESSOR:
               MaybePrintField(bp.expression, "Expression");
               fatalf("\tBytes: %hhu\n", bp.num_bytes);
               fatalf("\tAccess kind: %s\n",
                     ProcessorBreakpointAccessKindToString(bp.access_kind));
               break;
         }

         // Test for call to get information on a single user breakpoint
         struct Breakpoint _bp;
         GetBreakpoint(&ctx, bp.uid, &res, &_bp);

         // See if the breakpoint has been resolved. Not using an iterator
         // here, at the moment, because we can only get back one or zero.
         uint16_t num_locs;
         GetBreakpointLocations(&ctx, bp.uid, &res, &num_locs);
         if (num_locs == 1)
         {
            struct BreakpointLocation loc;
            loc.address = PopU64(&ctx.reply);
            PopString(&ctx.reply, &loc.module_name);
            PopString(&ctx.reply, &loc.filename);
            loc.actual_line_num = PopU32(&ctx.reply);

            fatalf("\t---------\n");
            fatalf("\tResolved address: 0x%llx\n", loc.address);
            MaybePrintField(loc.module_name, "Module");
            MaybePrintField(loc.module_name, "Filename");
            fatalf("\tActual line number: %u\n",
                  loc.actual_line_num);
         }
         else
         {
            fatalf("\tUnresolved\n");
         }
      }
      struct BufIterator fn_overload_it;
      struct FunctionOverload overload;
      GetFunctionOverloads(&ctx, &res, "SomeFunction", &fn_overload_it);
      while (FunctionOverloadIt_Next(&fn_overload_it, &overload))
      {
         fatalf("Overload %u; sig: ", overload.id);
         if (overload.fn_sig && overload.fn_sig->len)
         {
            fatalf("%.*s\n", overload.fn_sig->len,
                  (char*)overload.fn_sig->data);
         }
      }

      rdbg_Id bp_id;
      AddBreakpointAtFn(&ctx, "SomeFunction", 0, "", &res, &bp_id);
      AddBreakpointAtFilenameLine(&ctx, "C:\\path\\to\\fn_overloads.cpp", 21,
         "", &res, &bp_id);

      AddBreakpointAtAddress(&ctx, 0x7FF7F592B703, "", &res, &bp_id);
      AddProcessorBreakpoint(&ctx, "&var", 4,
      RDBG_PROCESSOR_BREAKPOINT_ACCESS_KIND_WRITE, "", &res, &bp_id);
      SetBreakpointCondition(&ctx, bp_id, "$rax == 0", &res);
      UpdateBreakpointLine(&ctx, bp_id, 22, &res);

      EnableBreakpoint(&ctx, bp_id, false, &res);
      EnableBreakpoint(&ctx, bp_id, true, &res);
      DeleteBreakpoint(&ctx, bp_id, &res);
      DeleteAllBreakpoints(&ctx, &res);

      rdbg_Id watch_id;
      AddWatch(&ctx, 1, "0xf0c / 0xa", "testing\nblah", &res, &watch_id);

      struct BufIterator watch_it;
      GetWatches(&ctx, 1, &res, &watch_it);
      struct Watch watch;
      while (WatchExpressionIt_Next(&watch_it, &watch))
      {
         fatalf("Watch %hu\n", watch.uid);
         if (watch.expression && watch.expression->len)
         {
            fatalf("\tWatch expression: '%.*s'\n",
                  watch.expression->len,
                  (char*)watch.expression->data);
         }
         if (watch.comment && watch.comment->len)
         {
            fatalf("\tWatch comment: '%.*s'\n",
                  watch.comment->len,
                  (char*)watch.comment->data);
         }
      }
      UpdateWatchExpression(&ctx, 37, "expr * expr", &res);
      UpdateWatchComment(&ctx, 37, "something left after", &res);
      DeleteWatch(&ctx, 42, &res);
      DeleteAllWatches(&ctx, 1, &res);

      ExitDebugger(&ctx, &res);
      */

      if (ContextHadError(&ctx))
      {
         fatalf("[ERROR] %s (cmd-err:%s)(reply-err:%s)\n",
               ctx.last_error,
               ctx.cmd.err ? "true" : "false",
               ctx.reply.err ? "true" : "false");
      }
      CloseConnection(&ctx);
   }
   else
   {
		  fatalf("Failed to connect");
      fatalf(ctx.last_error);
   }
}

void DebugEventsSample(char* server_name)
{
   HANDLE pipe_handle;
   char last_error[ERROR_MSG_LEN];
   last_error[0] = 0;

   if (InitConnection(server_name, DebugEventsPipe, sizeof(last_error),
            last_error, &pipe_handle))
   {
      // blocking read for testing events
      while (1)
      {
         static uint8_t dbg_evt_buf[REPLY_BUF_SIZE];
         struct Buffer dbg_evt = {
            .data = dbg_evt_buf,
            .capacity = sizeof(dbg_evt_buf)
         };

         DWORD bytes_read = 0;
         if (ReadFile(pipe_handle, dbg_evt.data, REPLY_BUF_SIZE, &bytes_read,
                  NULL))
         {
            dbg_evt.curr = dbg_evt.data;
            WriteDebugEvent(&dbg_evt);
         }
         else
         {
            fatalf("ReadFile FAIL: err=%u\n", GetLastError());
         }
      }
   }
   else
   {
      fatalf(last_error);
   }
}

int main(int argc, char** argv)
{
   if (argc == 3)
   {
      char* server_name = argv[1];

			printf("Connecting to remedybg server '%s'\n", server_name);

			if(strcmp(argv[2], "start-debugging") == 0)
			{
				DebugControlSample(server_name, true);
			}
			else if(strcmp(argv[2], "stop-debugging") == 0)
			{
				DebugControlSample(server_name, false);
			}
			else
			{
				fatalf("Unrecognized command '%s'\n", argv[2]);
			}
			printf("Successful\n");
      /* Two different samples for demonstrating the debug control pipe and
       * debug events pipe, respectively.
       *
         DebugControlSample(server_name);
         DebugEventsSample(server_name);
      */
   }
   else
   {
      fatalf("usage: %s server-name [start or stop]-debugging\n", argv[0]);
   }
   return 0;
}
