/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "pal.h"
#include "pal_common.h"
#include "defs.h"

static int
sess_event_dequeue(uint8_t dev_id, struct dao_lc_cmd_event *ev)
{
	uint64_t timeout;
	int ret;
	/* Set a timeout of 1 second. */
	timeout = rte_get_timer_cycles() + rte_get_timer_hz();
	do
	{
		ret = dao_liquid_crypto_cmd_event_dequeue(dev_id, ev, 1);
		if (ret == 1)
			break;

		if (rte_get_timer_cycles() > timeout)
		{
			fprintf(stderr, "Operation timed out\n");
			break;
		}
	} while (ret == 0);

	if (ret != 1)
	{
		fprintf(stderr, "Could not dequeue operation\n");
		return -1;
	}

	return 0;
}

int sym_create_session(uint16_t dev_id,
			struct dao_lc_sym_ctx cry_session,struct dao_lc_cmd_event *event, uint8_t reconfigure, uint64_t sess_cookie)
{
	int ret;

	if (reconfigure)
		sym_session_cleanup(event, dev_id);
	/* Create Crypto session*/

	ret = dao_liquid_crypto_sym_sess_create(dev_id, &cry_session, sess_cookie);
	if (ret < 0) {
		printf("Could not create session");
		return 0;
	}
	ret = sess_event_dequeue(dev_id, event);
	if (ret < 0) {
		printf("Could not dequeue session event");
		return 0;
	}

	return 1;
}

bool pal_is_hw_sym_algos_supported(int algo)
{
	return true;
}

int sym_session_cleanup(struct dao_lc_cmd_event *event, int dev_id)
{
	int ret = 0;
	if (event != NULL) {
		uint64_t sess_cookie = event->sess_event.sess_cookie;
		ret = dao_liquid_crypto_sym_sess_destroy(dev_id, event->sess_event.sess_id,
				event->sess_event.sess_cookie);
		if (ret < 0) {
			printf("Could not destroy session");
			return -1;
		}
		ret = sess_event_dequeue(dev_id, event);
		if (ret < 0) {
			printf("Could not dequeue session event");
			return -1;
		}

		PAL_ASSERT(event->event_type == DAO_LC_CMD_EVENT_SESS_DESTROY, "Invalid event type");
		PAL_ASSERT(event->sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");
	}

	return 1;
}

int pal_asym_create_session(uint16_t dev_id, struct rte_crypto_asym_xform *xform,
			struct rte_cryptodev_asym_session **sess)
{
	return 1;
}

int pal_sym_poll(uint8_t dev_id, uint16_t qp_id, async_job async_cb)
{
	return 0;
}

int pal_asym_poll(uint8_t dev_id, uint16_t qp_id, user_callback_fn callback)
{
	return 0;
}

int pal_get_thread_id()
{
	unsigned int lcore = rte_lcore_id();

	if (lcore == LCORE_ID_ANY) {
		ossl_log(OSSL_LOG_ERR, "%s: lcore :%d\n", __FUNCTION__, lcore);
		return -1;
	}

	return lcore;
}
