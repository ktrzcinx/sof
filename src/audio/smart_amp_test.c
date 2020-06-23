// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2020 Intel Corporation. All rights reserved.
//
// Author: Bartosz Kokoszko <bartoszx.kokoszko@linux.intel.com>

#include <sof/audio/smart_amp_test.h>
#include <sof/trace/trace.h>
#include <sof/drivers/ipc.h>
#include <sof/ut.h>

static const struct comp_driver comp_smart_amp;

/* 167a961e-8ae4-11ea-89f1-000c29ce1635 */
DECLARE_SOF_RT_UUID("smart_amp-test", smart_amp_comp_uuid, 0x167a961e, 0x8ae4,
		    0x11ea, 0x89, 0xf1, 0x00, 0x0c, 0x29, 0xce, 0x16, 0x35);

DECLARE_TR_CTX(smart_amp_comp_tr, SOF_UUID(smart_amp_comp_uuid),
	       LOG_LEVEL_INFO);

struct smart_amp_data {
	struct sof_smart_amp_config config;
	struct comp_model_data model;

	struct comp_buffer *source_buf; /**< stream source buffer */
	struct comp_buffer *feedback_buf; /**< feedback source buffer */
	struct comp_buffer *sink_buf; /**< sink buffer */

	smart_amp_proc process;

	uint32_t in_channels;
	uint32_t out_channels;
};

static struct comp_dev *smart_amp_new(const struct comp_driver *drv,
				      struct sof_ipc_comp *comp)
{
	struct comp_dev *dev;
	struct sof_ipc_comp_process *sa;
	struct sof_ipc_comp_process *ipc_sa =
		(struct sof_ipc_comp_process *)comp;
	struct smart_amp_data *sad;
	struct sof_smart_amp_config *cfg;
	size_t bs;
	int ret;

	dev = comp_alloc(drv, COMP_SIZE(struct sof_ipc_comp_process));
	if (!dev)
		return NULL;

	comp_info(dev, "smart_amp_new(): alloc");

	sad = rzalloc(SOF_MEM_ZONE_RUNTIME, 0, SOF_MEM_CAPS_RAM, sizeof(*sad));

	comp_info(dev, "smart_amp_new(): sad");

	if (!sad) {
		rfree(dev);
		return NULL;
	}

	comp_set_drvdata(dev, sad);

	comp_info(dev, "smart_amp_new(): drv");

	sa = COMP_GET_IPC(dev, sof_ipc_comp_process);

	comp_info(dev, "smart_amp_new(): ipc");

	ret = memcpy_s(sa, sizeof(*sa), ipc_sa,
		       sizeof(struct sof_ipc_comp_process));
	assert(!ret);

	comp_info(dev, "smart_amp_new(): memcpy");

	cfg = (struct sof_smart_amp_config *)ipc_sa->data;
	bs = ipc_sa->size;

	comp_info(dev, "smart_amp_new(): if");

	if ((bs > 0) && (bs < sizeof(struct sof_smart_amp_config))) {
		comp_err(dev, "smart_amp_new(): failed to apply config");

		if (sad)
			rfree(sad);
		rfree(sad);
		return NULL;
	}

	comp_info(dev, "smart_amp_new(): if2");

	memcpy_s(&sad->config, sizeof(struct sof_smart_amp_config), cfg, bs);

	comp_info(dev, "smart_amp_new(): memcpy");

	dev->state = COMP_STATE_READY;

	return dev;
}

static int smart_amp_set_config(struct comp_dev *dev,
				struct sof_ipc_ctrl_data *cdata)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	struct sof_smart_amp_config *cfg;
	size_t bs;

	/* Copy new config, find size from header */
	cfg = (struct sof_smart_amp_config *)cdata->data->data;
	bs = cfg->size;

	comp_dbg(dev, "smart_amp_set_config(), actual blob size = %u, expected blob size = %u",
		 bs, sizeof(struct sof_smart_amp_config));

	if (bs != sizeof(struct sof_smart_amp_config)) {
		comp_err(dev, "smart_amp_set_config(): invalid blob size, actual blob size = %u, expected blob size = %u",
			 bs, sizeof(struct sof_smart_amp_config));
		return -EINVAL;
	}

	memcpy_s(&sad->config, sizeof(struct sof_smart_amp_config), cfg,
		 sizeof(struct sof_smart_amp_config));

	return 0;
}

static int smart_amp_get_config(struct comp_dev *dev,
				struct sof_ipc_ctrl_data *cdata, int size)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	size_t bs;
	int ret = 0;

	// Copy back to user space
	bs = sad->config.size;

	comp_dbg(dev, "smart_amp_set_config(), actual blob size = %u, expected blob size = %u",
		 bs, sizeof(struct sof_smart_amp_config));

	if (bs == 0 || bs > size)
		return -EINVAL;

	ret = memcpy_s(cdata->data->data, size, &sad->config, bs);
	assert(!ret);

	cdata->data->abi = SOF_ABI_VERSION;
	cdata->data->size = bs;

	return ret;
}

static int smart_amp_ctrl_get_bin_data(struct comp_dev *dev,
				       struct sof_ipc_ctrl_data *cdata,
				       int size)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	int ret = 0;

	assert(sad);

	switch (cdata->data->type) {
	case SOF_SMART_AMP_CONFIG:
		ret = smart_amp_get_config(dev, cdata, size);
		break;
	case SOF_SMART_AMP_MODEL:
		ret = comp_get_model(dev, &sad->model, cdata, size);
		break;
	default:
		comp_err(dev, "smart_amp_ctrl_get_bin_data(): unknown binary data type");
		break;
	}

	return ret;
}

static int smart_amp_ctrl_get_data(struct comp_dev *dev,
				   struct sof_ipc_ctrl_data *cdata, int size)
{
	int ret = 0;

	comp_info(dev, "smart_amp_ctrl_get_data() size: %d", size);

	switch (cdata->cmd) {
	case SOF_CTRL_CMD_BINARY:
		ret = smart_amp_ctrl_get_bin_data(dev, cdata, size);
		break;
	default:
		comp_err(dev, "smart_amp_ctrl_get_data(): invalid cdata->cmd");
		return -EINVAL;
	}

	return ret;
}

static int smart_amp_ctrl_set_bin_data(struct comp_dev *dev,
				       struct sof_ipc_ctrl_data *cdata)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	int ret = 0;

	assert(sad);

	if (dev->state != COMP_STATE_READY) {
		/* It is a valid request but currently this is not
		 * supported during playback/capture. The driver will
		 * re-send data in next resume when idle and the new
		 * configuration will be used when playback/capture
		 * starts.
		 */
		comp_err(dev, "smart_amp_ctrl_set_bin_data(): driver is busy");
		return -EBUSY;
	}

	switch (cdata->data->type) {
	case SOF_SMART_AMP_CONFIG:
		ret = smart_amp_set_config(dev, cdata);
		break;
	case SOF_SMART_AMP_MODEL:
		ret = comp_set_model(dev, &sad->model, cdata);
		break;
	default:
		comp_err(dev, "smart_amp_ctrl_set_bin_data(): unknown binary data type");
		break;
	}

	return ret;
}

static int smart_amp_ctrl_set_data(struct comp_dev *dev,
				   struct sof_ipc_ctrl_data *cdata)
{
	int ret = 0;

	/* Check version from ABI header */
	if (SOF_ABI_VERSION_INCOMPATIBLE(SOF_ABI_VERSION, cdata->data->abi)) {
		comp_err(dev, "smart_amp_ctrl_set_data(): invalid version");
		return -EINVAL;
	}

	switch (cdata->cmd) {
	case SOF_CTRL_CMD_ENUM:
		comp_info(dev, "smart_amp_ctrl_set_data(), SOF_CTRL_CMD_ENUM");
		break;
	case SOF_CTRL_CMD_BINARY:
		comp_info(dev, "smart_amp_ctrl_set_data(), SOF_CTRL_CMD_BINARY");
		ret = smart_amp_ctrl_set_bin_data(dev, cdata);
		break;
	default:
		comp_err(dev, "smart_amp_ctrl_set_data(): invalid cdata->cmd");
		ret = -EINVAL;
		break;
	}

	return ret;
}

/* used to pass standard and bespoke commands (with data) to component */
static int smart_amp_cmd(struct comp_dev *dev, int cmd, void *data,
			 int max_data_size)
{
	struct sof_ipc_ctrl_data *cdata = data;

	comp_info(dev, "smart_amp_cmd(): cmd: %d", cmd);

	switch (cmd) {
	case COMP_CMD_SET_DATA:
		return smart_amp_ctrl_set_data(dev, cdata);
	case COMP_CMD_GET_DATA:
		return smart_amp_ctrl_get_data(dev, cdata, max_data_size);
	default:
		return -EINVAL;
	}
}

static void smart_amp_free(struct comp_dev *dev)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);

	comp_info(dev, "smart_amp_free()");

	comp_free_model_data(dev, &sad->model);
	rfree(sad);
	rfree(dev);
}

static int smart_amp_verify_params(struct comp_dev *dev,
				   struct sof_ipc_stream_params *params)
{
	int ret;

	comp_info(dev, "smart_amp_verify_params()");

	ret = comp_verify_params(dev, BUFF_PARAMS_CHANNELS, params);
	if (ret < 0) {
		comp_err(dev, "volume_verify_params() error: comp_verify_params() failed.");
		return ret;
	}

	return 0;
}

static int smart_amp_params(struct comp_dev *dev,
			    struct sof_ipc_stream_params *params)
{
	int err;

	comp_info(dev, "smart_amp_params()");

	err = smart_amp_verify_params(dev, params);
	if (err < 0) {
		comp_err(dev, "smart_amp_params(): pcm params verification failed.");
		return -EINVAL;
	}

	return 0;
}

static int data_bits(const struct audio_stream *stream)
{
	switch(stream->frame_fmt) {
		case SOF_IPC_FRAME_S16_LE:
			return 16;
		case SOF_IPC_FRAME_S24_4LE:
			return 24;
		case SOF_IPC_FRAME_S32_LE:
			return 32;
		case SOF_IPC_FRAME_FLOAT:
			return 31;
		default:
			return -1;
	}
}

static void smart_amp_dump(const struct comp_dev *dev)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	struct comp_buffer *buff;

	buff = sad->source_buf;
	//buffer_control_invalidate(buff);
	comp_err(dev, "    source_buf addr: %X channels %d rate %d fmt %d",
		(uint32_t)buff, buff ? buff->stream.channels : -1,
		buff ? buff->stream.rate : -1, buff ? data_bits(&buff->stream) : -1);
	buff = sad->sink_buf;
	//buffer_control_invalidate(buff);
	comp_err(dev, "    sink_buf addr: %X channels %d rate %d fmt %d",
		(uint32_t)buff, buff ? buff->stream.channels : -1,
		buff ? buff->stream.rate : -1, buff ? data_bits(&buff->stream) : -1);
	buff = sad->feedback_buf;
	//buffer_control_invalidate(buff);
	comp_err(dev, "    feedback_buf addr: %X channels %d rate %d fmt %d",
		(uint32_t)buff, buff ? buff->stream.channels : -1,
		buff ? buff->stream.rate : -1, buff ? data_bits(&buff->stream) : -1);
}

static int smart_amp_trigger(struct comp_dev *dev, int cmd)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	int ret = 0;

	trace_point(0xBECA0011);
	comp_err(dev, "smart_amp_trigger(), command = %u", cmd);

	ret = comp_set_state(dev, cmd);

	if (ret == COMP_STATUS_STATE_ALREADY_SET)
		ret = PPL_STATUS_PATH_STOP;

	smart_amp_dump(dev);
	switch (cmd) {
	case COMP_TRIGGER_START:
	case COMP_TRIGGER_RELEASE:
		buffer_zero(sad->feedback_buf);
		break;
	case COMP_TRIGGER_PAUSE:
	case COMP_TRIGGER_STOP:
		break;
	default:
		break;
	}
	trace_point(0xBECA0012);

	return ret;
}

static int smart_amp_process_s16(struct comp_dev *dev,
				 const struct audio_stream *source,
				 const struct audio_stream *sink,
				 uint32_t frames, int8_t *chan_map)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	int16_t *src;
	int16_t *dest;
	uint32_t in_frag = 0;
	uint32_t out_frag = 0;
	int i;
	int j;

	comp_dbg(dev, "smart_amp_process_s16()");

	for (i = 0; i < frames; i++) {
		for (j = 0 ; j < sad->out_channels; j++) {
			if (chan_map[j] != -1) {
				src = audio_stream_read_frag_s16(source,
								 in_frag +
								 chan_map[j]);
				dest = audio_stream_write_frag_s16(sink,
								   out_frag);
				*dest = *src;
			}
			out_frag++;
		}
		in_frag += source->channels;
	}
	return 0;
}

static int smart_amp_process_s32(struct comp_dev *dev,
				 const struct audio_stream *source,
				 const struct audio_stream *sink,
				 uint32_t frames, int8_t *chan_map)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	int32_t *src;
	int32_t *dest;
	uint32_t in_frag = 0;
	uint32_t out_frag = 0;
	int i;
	int j;

	comp_dbg(dev, "smart_amp_process_s32()");

	for (i = 0; i < frames; i++) {
		for (j = 0 ; j < sad->out_channels; j++) {
			if (chan_map[j] != -1) {
				src = audio_stream_read_frag_s32(source,
								 in_frag +
								 chan_map[j]);
				dest = audio_stream_write_frag_s32(sink,
								   out_frag);
				*dest = *src;
			}
			out_frag++;
		}
		in_frag += source->channels;
	}

	return 0;
}

static smart_amp_proc get_smart_amp_process(struct comp_dev *dev)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);

	switch (sad->source_buf->stream.frame_fmt) {
	case SOF_IPC_FRAME_S16_LE:
		return smart_amp_process_s16;
	case SOF_IPC_FRAME_S24_4LE:
	case SOF_IPC_FRAME_S32_LE:
		return smart_amp_process_s32;
	default:
		comp_err(dev, "smart_amp_process() error: not supported frame format");
		return NULL;
	}
}

static int smart_amp_copy(struct comp_dev *dev)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	uint32_t avail_passthrough_frames;
	uint32_t avail_feedback_frames;
	uint32_t avail_frames;
	uint32_t source_bytes;
	uint32_t sink_bytes;
	uint32_t feedback_bytes;
	uint32_t source_flags = 0;
	uint32_t sink_flags = 0;
	uint32_t feedback_flags = 0;
	int ret = 0;
	static int dump = 0;

	trace_point(0xBECA0021);

	comp_dbg(dev, "smart_amp_copy()");

	if (!dump) {
		smart_amp_dump(dev);
		++dump;
	}


	buffer_lock(sad->source_buf, &source_flags);
	buffer_lock(sad->sink_buf, &sink_flags);

	/* available bytes and samples calculation */
	avail_passthrough_frames =
		audio_stream_avail_frames(&sad->source_buf->stream,
					  &sad->sink_buf->stream);

	buffer_unlock(sad->source_buf, source_flags);
	buffer_unlock(sad->sink_buf, sink_flags);

	avail_frames = avail_passthrough_frames;

	buffer_lock(sad->feedback_buf, &feedback_flags);
	dcache_invalidate_region(sad->feedback_buf->source,
				 sizeof(struct comp_dev));
	if (sad->feedback_buf->source->state == dev->state) {
		/* feedback */
		avail_feedback_frames = sad->feedback_buf->stream.avail /
			audio_stream_frame_bytes(&sad->feedback_buf->stream);

		avail_frames = MIN(avail_passthrough_frames,
				   avail_feedback_frames);

		feedback_bytes = avail_frames *
			audio_stream_frame_bytes(&sad->feedback_buf->stream);

		buffer_unlock(sad->feedback_buf, feedback_flags);

		comp_dbg(dev, "smart_amp_copy(): processing %d feedback frames (avail_passthrough_frames: %d)",
			 avail_frames, avail_passthrough_frames);

		sad->process(dev, &sad->feedback_buf->stream,
			     &sad->sink_buf->stream, avail_frames,
			     sad->config.feedback_ch_map);

		comp_update_buffer_consume(sad->feedback_buf, feedback_bytes);
	} else {
		buffer_unlock(sad->feedback_buf, feedback_flags);
	}

	buffer_lock(sad->sink_buf, &sink_flags);
	sink_bytes = avail_frames *
		audio_stream_frame_bytes(&sad->sink_buf->stream);
	buffer_unlock(sad->sink_buf, sink_flags);

	/* bytes calculation */
	buffer_lock(sad->source_buf, &source_flags);
	source_bytes = avail_frames *
		audio_stream_frame_bytes(&sad->source_buf->stream);
	buffer_unlock(sad->source_buf, source_flags);

	/* process data */
	sad->process(dev, &sad->source_buf->stream, &sad->sink_buf->stream,
		     avail_frames, sad->config.source_ch_map);

	/* source/sink buffer pointers update */
	comp_update_buffer_consume(sad->source_buf, source_bytes);
	comp_update_buffer_produce(sad->sink_buf, sink_bytes);

	trace_point(0xBECA0022);

	return ret;
}

static int smart_amp_reset(struct comp_dev *dev)
{
	comp_info(dev, "smart_amp_reset()");

	comp_set_state(dev, COMP_TRIGGER_RESET);

	return 0;
}

static int smart_amp_prepare(struct comp_dev *dev)
{
	struct smart_amp_data *sad = comp_get_drvdata(dev);
	struct comp_buffer *source_buffer;
	struct list_item *blist;
	int ret;

	trace_point(0xBECA0001);
	comp_err(dev, "smart_amp_prepare()");

	ret = comp_set_state(dev, COMP_TRIGGER_PREPARE);
	if (ret < 0)
		return ret;

	if (ret == COMP_STATUS_STATE_ALREADY_SET)
		return PPL_STATUS_PATH_STOP;

	/* searching for stream and feedback source buffers */
	list_for_item(blist, &dev->bsource_list) {
		source_buffer = container_of(blist, struct comp_buffer,
					     sink_list);
		buffer_control_invalidate(source_buffer);
		if (source_buffer->source->comp.type == SOF_COMP_DEMUX)
			sad->feedback_buf = source_buffer;
		else
			sad->source_buf = source_buffer;
	}

	sad->sink_buf = list_first_item(&dev->bsink_list, struct comp_buffer,
					source_list);

	comp_err(dev, "smart_amp_prepare() 3.2 FB: %X SRC: %X DST: %X", (uint32_t)sad->feedback_buf, (uint32_t)sad->source_buf, (uint32_t)sad->sink_buf);
	comp_err(dev, "smart_amp_prepare() 3.5 sad %X", (uint32_t)sad);

	sad->in_channels = sad->source_buf->stream.channels;
	sad->out_channels = sad->sink_buf->stream.channels;

	sad->feedback_buf->stream.channels = sad->config.feedback_channels;
	sad->feedback_buf->stream.rate = sad->source_buf->stream.rate;
	comp_err(dev, "smart_amp_prepare() 3.88");

	/* TODO:
	 * ATM feedback buffer frame_fmt is hardcoded to s32_le. It should be
	 * removed when parameters negotiation between pipelines will prepared
	 */
	sad->feedback_buf->stream.frame_fmt = SOF_IPC_FRAME_S32_LE;
	buffer_control_writeback(sad->feedback_buf);
	comp_err(dev, "smart_amp_prepare() 4");

	sad->process = get_smart_amp_process(dev);
	if (!sad->process) {
		comp_err(dev, "smart_amp_prepare(): get_smart_amp_process failed");
		return -EINVAL;
	}
	comp_err(dev, "smart_amp_prepare() 4");

	smart_amp_dump(dev);

	comp_err(dev, "smart_amp_prepare() end");
	trace_point(0xBECA0002);

	return 0;
}

static const struct comp_driver comp_smart_amp = {
	.type = SOF_COMP_SMART_AMP,
	.uid = SOF_RT_UUID(smart_amp_comp_uuid),
	.tctx = &smart_amp_comp_tr,
	.ops = {
		.create = smart_amp_new,
		.free = smart_amp_free,
		.params = smart_amp_params,
		.prepare = smart_amp_prepare,
		.cmd = smart_amp_cmd,
		.trigger = smart_amp_trigger,
		.copy = smart_amp_copy,
		.reset = smart_amp_reset,
	},
};

static SHARED_DATA struct comp_driver_info comp_smart_amp_info = {
	.drv = &comp_smart_amp,
};

static void sys_comp_smart_amp_init(void)
{
	comp_register(platform_shared_get(&comp_smart_amp_info,
					  sizeof(comp_smart_amp_info)));
}

DECLARE_MODULE(sys_comp_smart_amp_init);
