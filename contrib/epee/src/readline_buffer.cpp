// Copyright (c) 2018-2024, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "readline_buffer.h"
#include <readline/readline.h>
#include <readline/history.h>
#include <iostream>
#include <boost/thread/mutex.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/algorithm/string.hpp>

static void install_line_handler();
static void remove_line_handler();

static boost::mutex sync_mutex;
static rdln::linestatus line_stat;
static char *the_line;

namespace
{
  rdln::readline_buffer* current = NULL;
}

rdln::suspend_readline::suspend_readline()
: m_buffer(NULL), m_restart(false)
{
  m_buffer = current;
  if(!m_buffer)
    return;
  m_restart = m_buffer->is_running();
  if(m_restart)
    m_buffer->stop();
}

rdln::suspend_readline::~suspend_readline()
{
  if(!m_buffer)
    return;
  if(m_restart)
    m_buffer->start();
}

std::vector<std::string>& rdln::readline_buffer::completion_commands()
{
  static std::vector<std::string> commands = {"exit"};
  return commands;
}

rdln::readline_buffer::readline_buffer()
: std::stringbuf(), m_cout_buf(NULL), m_prompt_length(0)
{
  current = this;
}

void rdln::readline_buffer::start()
{
  if(m_cout_buf != NULL)
    return;
  m_cout_buf = std::cout.rdbuf();
  std::cout.rdbuf(this);
  install_line_handler();
}

void rdln::readline_buffer::stop()
{
  if(m_cout_buf == NULL)
    return;
  std::cout.rdbuf(m_cout_buf);
  m_cout_buf = NULL;
  remove_line_handler();
}

rdln::linestatus rdln::readline_buffer::get_line(std::string& line) const
{
  boost::lock_guard<boost::mutex> lock(sync_mutex);
  line_stat = rdln::partial;
  if (!m_cout_buf)
  {
    line = "";
    return rdln::full;
  }
  rl_callback_read_char();
  if (line_stat == rdln::full)
  {
    line = the_line;
    free(the_line);
    the_line = NULL;
  }
  return line_stat;
}

void rdln::readline_buffer::set_prompt(const std::string& prompt)
{
  if(m_cout_buf == NULL)
    return;
  boost::lock_guard<boost::mutex> lock(sync_mutex);
  rl_set_prompt(std::string(m_prompt_length, ' ').c_str());
  rl_redisplay();
  rl_set_prompt(prompt.c_str());
  rl_redisplay();
  m_prompt_length = prompt.size();
}

void rdln::readline_buffer::add_completion(const std::string& command)
{
  if(std::find(completion_commands().begin(), completion_commands().end(), command) != completion_commands().end())
    return;
  completion_commands().push_back(command);
}

const std::vector<std::string>& rdln::readline_buffer::get_completions()
{
  return completion_commands();
}

int rdln::readline_buffer::sync()
{
  boost::lock_guard<boost::mutex> lock(sync_mutex);
#if RL_READLINE_VERSION < 0x0700
  char lbuf[2] = {0,0};
  char *line = NULL;
  int end = 0, point = 0;
#endif

  if (rl_end || (rl_prompt && *rl_prompt))
  {
#if RL_READLINE_VERSION >= 0x0700
    rl_clear_visible_line();
#else
    line = rl_line_buffer;
    end = rl_end;
    point = rl_point;
    rl_line_buffer = lbuf;
    rl_end = 0;
    rl_point = 0;
    rl_save_prompt();
    rl_redisplay();
#endif
  }

  do
  {
    m_cout_buf->sputc( this->sgetc() );
  }
  while ( this->snextc() != EOF );

#if RL_READLINE_VERSION < 0x0700
  if (end || (rl_prompt && *rl_prompt))
  {
    rl_restore_prompt();
    rl_line_buffer = line;
    rl_end = end;
    rl_point = point;
  }
#endif
  rl_on_new_line();
  rl_redisplay();

  return 0;
}

static void handle_line(char* line)
{
  bool exit = false;
  if (line)
  {
    line_stat = rdln::full;
    the_line = line;
    std::string test_line = line;
    boost::trim_right(test_line);
    if(!test_line.empty())
    {
      add_history(test_line.c_str());
      history_set_pos(history_length);
      if (test_line == "exit" || test_line == "q")
        exit = true;
    }
  } else
  /* EOF */
  {
    line_stat = rdln::empty;
    exit = true;
  }
  rl_done = 1;
  if (exit)
    rl_set_prompt("");
  return;
}

static char* completion_matches(const char* text, int state)
{
  static size_t list_index;
  static size_t len;

  if(state == 0)
  {
    list_index = 0;
    len = strlen(text);
  }

  const std::vector<std::string>& completions = rdln::readline_buffer::get_completions();
  for(; list_index<completions.size(); )
  {
    const std::string& cmd = completions[list_index++];
    if(cmd.compare(0, len, text) == 0)
    {
      return strdup(cmd.c_str());
    }
  }

  return NULL;
}

static char** attempted_completion(const char* text, int start, int end)
{
  rl_attempted_completion_over = 1;
  return rl_completion_matches(text, completion_matches);
}

static void install_line_handler()
{
  rl_attempted_completion_function = attempted_completion;
  rl_callback_handler_install("", handle_line);
  stifle_history(500);
}

static void remove_line_handler()
{
  rl_replace_line("", 0);
  rl_set_prompt("");
  rl_redisplay();
  rl_callback_handler_remove();
}

void rdln::clear_screen()
{
  rl_clear_screen(0, 0);
}

