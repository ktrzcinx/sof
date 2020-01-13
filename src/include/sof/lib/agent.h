/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 */

#ifndef __SOF_LIB_AGENT_H__
#define __SOF_LIB_AGENT_H__

#include <sof/schedule/task.h>
#include <config.h>
#include <stdbool.h>
#include <stdint.h>

struct sof;

/* simple agent */
struct sa {
	uint64_t last_check;	/* time of last activity checking */
	uint64_t panic_timeout;	/* threshold of panic */
	uint64_t warn_timeout;	/* threshold of warning */
#if CONFIG_LOAD_CNT
	uint64_t last_gated_ticks[PLATFORM_CORE_COUNT];
	uint64_t last_art_ticks[PLATFORM_CORE_COUNT];
	int peak_loads[PLATFORM_CORE_COUNT];
#endif
	struct task work;
};

#if CONFIG_HAVE_AGENT

void sa_init(struct sof *sof, uint64_t timeout);

#else

static inline void sa_init(struct sof *sof, uint64_t timeout) { }

#endif

#endif /* __SOF_LIB_AGENT_H__ */
