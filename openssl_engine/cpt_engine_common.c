/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "cpt_engine.h"

extern OSSL_ASYNC_FD zero_fd;

int pause_async_job(void)
{
	ASYNC_JOB *job = ASYNC_get_current_job();
	if (job != NULL) {
		ASYNC_WAIT_CTX *wctx = ASYNC_get_wait_ctx(job);
		if (wctx != NULL) {
			size_t numfds = 0;
			ASYNC_WAIT_CTX_get_all_fds(wctx, NULL, &numfds);
			/* If wctx does not have an fd, then set it.
			 * This is needed for the speed test which select()s
			 * on fd
			 */
			if (numfds == 0)
				ASYNC_WAIT_CTX_set_wait_fd(wctx, NULL, zero_fd,
							   NULL, NULL);
		}
		ASYNC_pause_job();
	}
	return 0;
}

static inline void invoke_async_callback(ASYNC_WAIT_CTX *wctx_p)
{
    int (*callback)(void *arg);
    void *args;

    if(ASYNC_WAIT_CTX_get_callback(wctx_p, &callback, &args))
        (*callback)(args);
}

int ossl_handle_async_job(void *resumed_wctx, void *wctx_p, int numpipes,
    uint8_t *job_qsz, async_pipe_job_t *pip_jobs, bool pause_job)
{
  uint8_t job_index = 0, k = 0, wctx_found = 0;

  if (pause_job == ASYNC_JOB_PAUSE)
    return pause_async_job();

  if ((*job_qsz == 0))
  {
    pip_jobs[0].wctx_p = wctx_p;
    pip_jobs[0].counter = 1;
    *job_qsz = 1;
    if (pip_jobs[0].counter == numpipes)
    {
      if ((resumed_wctx == NULL) || (resumed_wctx != pip_jobs[0].wctx_p))
        invoke_async_callback(pip_jobs[0].wctx_p);
      (*job_qsz)--;
    }
  }
  else
  {
    for (job_index=0; job_index < *job_qsz; job_index++)
    {
      if (wctx_p == pip_jobs[job_index].wctx_p)
      {
        wctx_found = 1;
        pip_jobs[job_index].counter++;
        if (pip_jobs[job_index].counter == numpipes)
        {
          if ((resumed_wctx == NULL) || (resumed_wctx != pip_jobs[job_index].wctx_p))
            invoke_async_callback(pip_jobs[job_index].wctx_p);
          for (k = job_index; k < (*job_qsz - 1); k++)
          {
            pip_jobs[k].wctx_p = pip_jobs[k+1].wctx_p;
            pip_jobs[k].counter = pip_jobs[k+1].counter;
          }
          (*job_qsz)--;
        }
      }
    }
    if (!wctx_found) {
      pip_jobs[*job_qsz].wctx_p = wctx_p;
      (*job_qsz)++;
    }
  }

  return 0;
}

void ossl_handle_async_asym_job(void **wctx)
{
  void *args;
  int (*callback)(void *arg);
  ASYNC_WAIT_CTX **wctx_p = (ASYNC_WAIT_CTX **) wctx;

  if(ASYNC_WAIT_CTX_get_callback(*wctx_p, &callback, &args))
    (*callback)(args);
}
