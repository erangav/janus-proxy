/*! \file   janus_nosip.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus NoSIP plugin
 * \details  
 *
 * This is quite a basic plugin, as it only takes care of acting as an
 * RTP bridge. It is named "NoSIP" since, as the name suggests, signalling
 * takes no place here, and is entirely up to the application. The typical
 * usage of this application is something like this:
 * 
 * 1. a WebRTC application handles signalling on its own (e.g., SIP), but
 * needs to interact with a peer that doesn't support WebRTC (DTLS/ICE);
 * 2. it creates a handle with the NoSIP plugin, creates a JSEP SDP offer,
 * and passes it to the plugin;
 * 3. the plugin creates a barebone SDP that can be used to communicate
 * with the legacy peer, binds to the ports for RTP/RTCP, and sends this
 * plain SDP back to the application;
 * 4. the application uses this barebone SDP in its signalling, and expects
 * an answer from the peer;
 * 5. the SDP answer from the peer will be barebone as well, and so unfit
 * for WebRTC usage; as such, the application passes it to the plugin as
 * the answer to match the offer created before;
 * 6. the plugin matches the answer to the offer, and starts exchanging
 * RTP/RTCP with the legacy peer: media coming from the peer is relayed
 * via WebRTC to the application, and WebRTC stuff coming from the application
 * is relayed via plain RTP/RTCP to the legacy peer.
 *
 * The same behaviour can be followed if the application is the callee
 * instead, with the only difference being that the barebone offer will
 * come from the peer in this case, and the application will ask the
 * NoSIP plugin for a barebone answer instead.
 *
 * As you can see, the behaviour is pretty much the same as the SIP plugin,
 * with the key difference being that in this case there's no SIP stack in
 * the plugin itself. All signalling is left to the application, and Janus
 * (via the NoSIP plugin) is only responsible for bridging the media. This
 * might be more appropriate than the SIP plugin in cases where developers
 * want to keep control on the signalling layer, while still involving a
 * gateway of sorts. Of course, SIP is just an example here: other signalling
 * protocols may be involved as well (e.g., IAX, XMPP, others). The NoSIP
 * plugin, though, will generate and expect plain SDP, so you'll need to
 * take care of any adaptation that may be needed to make this work with
 * the signalling protocol of your choice.
 *
 * \section nosipapi NoSIP Plugin API
 *
 * The plugin mainly supports two requests, \c generate and \c process,
 * which are both asynchronous. The \c generate request take a JSEP offer
 * or answer, and generates a barebone SDP the "legacy" application can
 * use; the \c process request, on the other hand, processes a remote
 * barebone SDP, and matches it to the plugin may have generated before,
 * in order to then return a JSEP offer or answer that can be used to
 * setup a PeerConnection. 
 *
 * The \c generate request must be formatted as follows:
 *
\verbatim
{
	"request" : "generate",
	"info" : "<opaque string that the user can provide for context; optional>",
	"srtp" : "<whether to mandate (sdes_mandatory) or offer (sdes_optional) SRTP support; optional>",
	"srtp_profile" : "<SRTP profile to negotiate, in case SRTP is offered; optional>"
}
\endverbatim
 *
 * As anticipated, this requires a JSEP offer or answer passed via Janus
 * API as part of a WebRTC PeerConnection negotiation. If the conversion
 * of the WebRTC JSEP SDP to barebone SDP is successful, a \c generated
 * event is sent back to the user:
 *
\verbatim
{
	"event" : "generated",
	"type" : "<offer|answer, depending on the nature of the provided JSEP>",
	"sdp" : "<barebone SDP content>"
}
\endverbatim
 *
 * The \c process request, instead, must be formatted as follows:
 *
\verbatim
{
	"request" : "process",
	"type" : "<offer|answer, depending on the nature of the provided SDP>",
	"sdp" : "<barebone SDP to convert>"
	"info" : "<opaque string that the user can provide for context; optional>",
	"srtp" : "<whether to mandate (sdes_mandatory) or offer (sdes_optional) SRTP support; optional>",
	"srtp_profile" : "<SRTP profile to negotiate, in case SRTP is offered; optional>"
}
\endverbatim
 *
 * As anticipated, this requires a "legacy" SDP offer or answer passed via
 * NoSIP plugin messaging, which is why the caller must specify if it's an
 * offer or answer. If the request is successful, a \c processed event is
 * sent back to the user, along to the JSEP offer or answer that Janus
 * generated out of the barebone SDP:
 *
\verbatim
{
	"event" : "processed",
	"srtp" : "<whether the barebone SDP mandates (sdes_mandatory) or offers (sdes_optional) SRTP support; optional>"
}
\endverbatim
 *
 * To close a session you can use the \c hangup request, which needs no
 * additional arguments, as the whole context can be extracted from the
 * current state of the session in the plugin:
 *
\verbatim
{
	"request" : "hangup"
}
\endverbatim
 *
 * An \c hangingup event will be sent back, as this is an asynchronous request.
 *
 * Finally, just as in the SIP and SIPre plugins, the multimedia session
 * can be recorded. Considering the NoSIP plugin also assumes two peers
 * are in a call with each other (although it makes no assumptions on
 * the signalling that ties them together), it works exactly the same
 * way as the SIP and SIPre plugin do when it comes to recording.
 * Specifically, you make use of the \c recording request to either start
 * or stop a recording, using the following syntax:
 *
\verbatim
{
	"request" : "recording",
	"action" : "<start|stop, depending on whether you want to start or stop recording something>"
	"audio" : <true|false; whether or not our audio should be recorded>,
	"video" : <true|false; whether or not our video should be recorded>,
	"peer_audio" : <true|false; whether or not our peer's audio should be recorded>,
	"peer_video" : <true|false; whether or not our peer's video should be recorded>,
	"filename" : "<base path/filename to use for all the recordings>"
}
\endverbatim
 *
 * As you can see, this means that the two sides of conversation are recorded
 * separately, and so are the audio and video streams if available. You can
 * choose which ones to record, in case you're interested in just a subset.
 * The \c filename part is just a prefix, and dictates the actual filenames
 * that will be used for the up-to-four recordings that may need to be enabled.
 *
 * A \c recordingupdated event is sent back in case the request is successful.
 *
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <glib.h>

#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../record.h"
#include "../rtp.h"
#include "../rtpsrtp.h"
#include "../rtcp.h"
#include "../ip-utils.h"
#include "../sdp-utils.h"
#include "../utils.h"
#include "../sctp.h"
#include "../dtls.h"

/* Plugin information */
#define JANUS_NOSIP_VERSION			1
#define JANUS_NOSIP_VERSION_STRING	"0.0.1"
#define JANUS_NOSIP_DESCRIPTION		"This is a simple RTP bridging plugin that leaves signalling details (e.g., SIP) up to the application."
#define JANUS_NOSIP_NAME			"JANUS NoSIP plugin"
#define JANUS_NOSIP_AUTHOR			"Meetecho s.r.l."
#define JANUS_NOSIP_PACKAGE			"janus.plugin.nosip"

/* Plugin methods */
janus_plugin *create(void);
int janus_nosip_init(janus_callbacks *callback, const char *config_path);
void janus_nosip_destroy(void);
int janus_nosip_get_api_compatibility(void);
int janus_nosip_get_version(void);
const char *janus_nosip_get_version_string(void);
const char *janus_nosip_get_description(void);
const char *janus_nosip_get_name(void);
const char *janus_nosip_get_author(void);
const char *janus_nosip_get_package(void);
void janus_nosip_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_nosip_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_nosip_setup_media(janus_plugin_session *handle);
void janus_nosip_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet);
void janus_nosip_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet);
void janus_nosip_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet);
void janus_nosip_hangup_media(janus_plugin_session *handle);
void janus_nosip_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_nosip_query_session(janus_plugin_session *handle);


/* Plugin setup */
static janus_plugin janus_nosip_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_nosip_init,
		.destroy = janus_nosip_destroy,

		.get_api_compatibility = janus_nosip_get_api_compatibility,
		.get_version = janus_nosip_get_version,
		.get_version_string = janus_nosip_get_version_string,
		.get_description = janus_nosip_get_description,
		.get_name = janus_nosip_get_name,
		.get_author = janus_nosip_get_author,
		.get_package = janus_nosip_get_package,

		.create_session = janus_nosip_create_session,
		.handle_message = janus_nosip_handle_message,
		.setup_media = janus_nosip_setup_media,
		.incoming_rtp = janus_nosip_incoming_rtp,
		.incoming_rtcp = janus_nosip_incoming_rtcp,
		.incoming_data = janus_nosip_incoming_data,
		.hangup_media = janus_nosip_hangup_media,
		.destroy_session = janus_nosip_destroy_session,
		.query_session = janus_nosip_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_NOSIP_NAME);
	return &janus_nosip_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter generate_parameters[] = {
	{"info", JSON_STRING, 0},
	{"srtp", JSON_STRING, 0},
	{"srtp_profile", JSON_STRING, 0},
	{"update", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter process_parameters[] = {
	{"type", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"sdp", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"info", JSON_STRING, 0},
	{"srtp", JSON_STRING, 0},
	{"srtp_profile", JSON_STRING, 0},
	{"update", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter recording_parameters[] = {
	{"action", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"peer_audio", JANUS_JSON_BOOL, 0},
	{"peer_video", JANUS_JSON_BOOL, 0},
	{"filename", JSON_STRING, 0}
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;

static char *local_ip = NULL;
static uint16_t rtp_range_min = 10000;
static uint16_t rtp_range_max = 60000;
static gboolean rtcp_mux = 1;
static gchar *sdp_ip = NULL;
static uint64_t g_fir_freq = 21; /* 5 sec */



static GThread *handler_thread;
static void *janus_nosip_handler(void *data);
static void janus_nosip_hangup_media_internal(janus_plugin_session *handle);

typedef struct janus_nosip_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_nosip_message;
static GAsyncQueue *messages = NULL;
static janus_nosip_message exit_message;


typedef struct janus_nosip_media {
	char *remote_ip;
	int ready:1;
	gboolean autoack;
	gboolean require_srtp, has_srtp_local, has_srtp_remote;
	janus_srtp_profile srtp_profile;
//	int has_audio:1;
//	int audio_rtp_fd, audio_rtcp_fd;
//	int local_audio_rtp_port, remote_audio_rtp_port;
//	int local_audio_rtcp_port, remote_audio_rtcp_port;
//	guint32 audio_ssrc, audio_ssrc_peer;
//	int audio_pt;
//	const char *audio_pt_name;
//	srtp_t audio_srtp_in, audio_srtp_out;
//	srtp_policy_t audio_remote_policy, audio_local_policy;
//	gboolean audio_send, audio_recv;
//	gboolean audio_sendonly, audio_recvonly;
	int has_video:1;
	int media_rtp_fd/*, media_rtcp_fd*/;
	uint64_t    last_rx_packet;
	int local_media_rtp_port, remote_media_rtp_port;
//	int local_media_rtcp_port, remote_media_rtcp_port;
//	guint32 video_ssrc, video_ssrc_peer;
//	guint32 video_ssrc_num;
//	guint32 video_ssrcs[10];
//	int video_pt;
//	const char *video_pt_name;
	srtp_t media_srtp_in, media_srtp_out;
	srtp_policy_t media_remote_policy, media_local_policy;
	gboolean media_send_first, media_recv_first; // For first packet
//	gboolean media_sendonly, media_recvonly;
	int has_application:1;
	//int local_application_port, remote_application_port;
	int application_pt;
	//int application_fd;
	const char *application_pt_name;
	srtp_t application_srtp_in, application_srtp_out;
	srtp_policy_t application_remote_policy, application_local_policy;
	janus_rtp_switching_context context;
	int pipefd[2];
	gboolean updated;
} janus_nosip_media;

typedef struct janus_nosip_session {
	janus_plugin_session *handle;
	gint64 sdp_version;
	janus_nosip_media media;	/* Media gatewaying stuff (same stuff as the SIP plugin) */
	janus_sctp_association* sctp_association;
	GThread *sctp_conn_thread;
	janus_sdp *sdp;				/* The SDP this user sent */
//	janus_recorder *arc;		/* The Janus recorder instance for this user's audio, if enabled */
//	janus_recorder *arc_peer;	/* The Janus recorder instance for the peer's audio, if enabled */
	janus_recorder *mrc;		/* The Janus recorder instance for this user's video, if enabled */
	janus_recorder *mrc_peer;	/* The Janus recorder instance for the peer's video, if enabled */
	janus_mutex rec_mutex;		/* Mutex to protect the recorders from race conditions */
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
	janus_mutex mutex;
	gint fir_seq;
	gint64 last_fir;
	gint64 remb_startup;
	gint64 last_remb;
} janus_nosip_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_nosip_srtp_cleanup(janus_nosip_session *session);

static void janus_nosip_session_destroy(janus_nosip_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void print_json(const char* title, const json_t *msg ) {
    char * msg_text = json_dumps(msg,JSON_INDENT(3) | JSON_PRESERVE_ORDER);
    JANUS_LOG(LOG_INFO, "%s\n%s\n", title, msg_text);
    free(msg_text);
}

static void janus_nosip_session_free(const janus_refcount *session_ref) {
	janus_nosip_session *session = janus_refcount_containerof(session_ref, janus_nosip_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	janus_sdp_destroy(session->sdp);
	session->sdp = NULL;
	g_free(session->media.remote_ip);
	session->media.remote_ip = NULL;
	janus_nosip_srtp_cleanup(session);
	session->handle = NULL;
	g_free(session);
	session = NULL;
}

static void janus_nosip_message_free(janus_nosip_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_nosip_session *session = (janus_nosip_session *)msg->handle->plugin_handle;
		janus_refcount_decrease(&session->ref);
	}
	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message)
		json_decref(msg->message);
	msg->message = NULL;
	if(msg->jsep)
		json_decref(msg->jsep);
	msg->jsep = NULL;

	g_free(msg);
}


/* SRTP stuff (in case we need SDES) */
static int janus_nosip_srtp_set_local(janus_nosip_session *session, gboolean video, char **profile, char **crypto) {
	if(session == NULL)
		return -1;
	/* Which SRTP profile are we going to negotiate? */
	int key_length = 0, salt_length = 0, master_length = 0;
	if(session->media.srtp_profile == JANUS_SRTP_AES128_CM_SHA1_32) {
		key_length = SRTP_MASTER_KEY_LENGTH;
		salt_length = SRTP_MASTER_SALT_LENGTH;
		master_length = SRTP_MASTER_LENGTH;
		*profile = g_strdup("AES_CM_128_HMAC_SHA1_32");
	} else if(session->media.srtp_profile == JANUS_SRTP_AES128_CM_SHA1_80) {
		key_length = SRTP_MASTER_KEY_LENGTH;
		salt_length = SRTP_MASTER_SALT_LENGTH;
		master_length = SRTP_MASTER_LENGTH;
		*profile = g_strdup("AES_CM_128_HMAC_SHA1_80");
#ifdef HAVE_SRTP_AESGCM
	} else if(session->media.srtp_profile == JANUS_SRTP_AEAD_AES_128_GCM) {
		key_length = SRTP_AESGCM128_MASTER_KEY_LENGTH;
		salt_length = SRTP_AESGCM128_MASTER_SALT_LENGTH;
		master_length = SRTP_AESGCM128_MASTER_LENGTH;
		*profile = g_strdup("AEAD_AES_128_GCM");
	} else if(session->media.srtp_profile == JANUS_SRTP_AEAD_AES_256_GCM) {
		key_length = SRTP_AESGCM256_MASTER_KEY_LENGTH;
		salt_length = SRTP_AESGCM256_MASTER_SALT_LENGTH;
		master_length = SRTP_AESGCM256_MASTER_LENGTH;
		*profile = g_strdup("AEAD_AES_256_GCM");
#endif
	} else {
		JANUS_LOG(LOG_ERR, "[NoSIP-%p] Unsupported SRTP profile\n", session);
		return -2;
	}
	JANUS_LOG(LOG_WARN, "[NoSIP-%p] %s\n", session, *profile);
	JANUS_LOG(LOG_WARN, "[NoSIP-%p] Key/Salt/Master: %d/%d/%d\n",
		session, master_length, key_length, salt_length);
	/* Generate key/salt */
	uint8_t *key = g_malloc0(master_length);
	srtp_crypto_get_random(key, master_length);
	/* Set SRTP policies */
	srtp_policy_t *policy =  &session->media.media_local_policy;
	switch(session->media.srtp_profile) {
		case JANUS_SRTP_AES128_CM_SHA1_32:
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy->rtp));
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtcp));
			break;
		case JANUS_SRTP_AES128_CM_SHA1_80:
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtp));
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtcp));
			break;
#ifdef HAVE_SRTP_AESGCM
		case JANUS_SRTP_AEAD_AES_128_GCM:
			srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy->rtp));
			srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy->rtcp));
			break;
		case JANUS_SRTP_AEAD_AES_256_GCM:
			srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy->rtp));
			srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy->rtcp));
			break;
#endif
		default:
			/* Will never happen? */
			JANUS_LOG(LOG_WARN, "[NoSIP-%p] Unsupported SRTP profile\n", session);
			break;
	}
	policy->ssrc.type = ssrc_any_inbound;
	policy->key = key;
	policy->next = NULL;
	/* Create SRTP context */
	srtp_err_status_t res = srtp_create( &session->media.media_srtp_out,  policy);
	if(res != srtp_err_status_ok) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Oops, error creating outbound SRTP session: %d (%s)\n", res, janus_srtp_error_str(res));
		g_free(*profile);
		*profile = NULL;
		g_free(key);
		policy->key = NULL;
		return -2;
	}
	/* Base64 encode the salt */
	*crypto = g_base64_encode(key, master_length);
	if(session->media.media_srtp_out ) {
		JANUS_LOG(LOG_VERB, "%s outbound SRTP session created\n", "Media");
	}
	return 0;
}
static int janus_nosip_srtp_set_remote(janus_nosip_session *session, gboolean video, const char *profile, const char *crypto) {
	if(session == NULL || profile == NULL || crypto == NULL)
		return -1;
	/* Which SRTP profile is being negotiated? */
	JANUS_LOG(LOG_WARN, "[NoSIP-%p] %s\n", session, profile);
	gsize key_length = 0, salt_length = 0, master_length = 0;
	if(!strcasecmp(profile, "AES_CM_128_HMAC_SHA1_32")) {
		session->media.srtp_profile = JANUS_SRTP_AES128_CM_SHA1_32;
		key_length = SRTP_MASTER_KEY_LENGTH;
		salt_length = SRTP_MASTER_SALT_LENGTH;
		master_length = SRTP_MASTER_LENGTH;
	} else if(!strcasecmp(profile, "AES_CM_128_HMAC_SHA1_80")) {
		session->media.srtp_profile = JANUS_SRTP_AES128_CM_SHA1_80;
		key_length = SRTP_MASTER_KEY_LENGTH;
		salt_length = SRTP_MASTER_SALT_LENGTH;
		master_length = SRTP_MASTER_LENGTH;
#ifdef HAVE_SRTP_AESGCM
	} else if(!strcasecmp(profile, "AEAD_AES_128_GCM")) {
		session->media.srtp_profile = JANUS_SRTP_AEAD_AES_128_GCM;
		key_length = SRTP_AESGCM128_MASTER_KEY_LENGTH;
		salt_length = SRTP_AESGCM128_MASTER_SALT_LENGTH;
		master_length = SRTP_AESGCM128_MASTER_LENGTH;
	} else if(!strcasecmp(profile, "AEAD_AES_256_GCM")) {
		session->media.srtp_profile = JANUS_SRTP_AEAD_AES_256_GCM;
		key_length = SRTP_AESGCM256_MASTER_KEY_LENGTH;
		salt_length = SRTP_AESGCM256_MASTER_SALT_LENGTH;
		master_length = SRTP_AESGCM256_MASTER_LENGTH;
#endif
	} else {
		JANUS_LOG(LOG_ERR, "[NoSIP-%p] Unsupported SRTP profile %s\n", session, profile);
		return -2;
	}
	JANUS_LOG(LOG_WARN, "[NoSIP-%p] Key/Salt/Master: %zu/%zu/%zu\n",
		session, master_length, key_length, salt_length);
	/* Base64 decode the crypto string and set it as the remote SRTP context */
	gsize len = 0;
	guchar *decoded = g_base64_decode(crypto, &len);
	if(len < master_length) {
		/* FIXME Can this happen? */
		g_free(decoded);
		return -3;
	}
	/* Set SRTP policies */
	srtp_policy_t *policy =  &session->media.media_remote_policy;
	switch(session->media.srtp_profile) {
		case JANUS_SRTP_AES128_CM_SHA1_32:
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy->rtp));
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtcp));
			break;
		case JANUS_SRTP_AES128_CM_SHA1_80:
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtp));
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtcp));
			break;
#ifdef HAVE_SRTP_AESGCM
		case JANUS_SRTP_AEAD_AES_128_GCM:
			srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy->rtp));
			srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy->rtcp));
			break;
		case JANUS_SRTP_AEAD_AES_256_GCM:
			srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy->rtp));
			srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy->rtcp));
			break;
#endif
		default:
			/* Will never happen? */
			JANUS_LOG(LOG_WARN, "[NoSIP-%p] Unsupported SRTP profile\n", session);
			break;
	}
	policy->ssrc.type = ssrc_any_inbound;
	policy->key = decoded;
	policy->next = NULL;
	/* Create SRTP context */
	srtp_err_status_t res = srtp_create(&session->media.media_srtp_in, policy);
	if(res != srtp_err_status_ok) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Oops, error creating inbound SRTP session: %d (%s)\n", res, janus_srtp_error_str(res));
		g_free(decoded);
		policy->key = NULL;
		return -2;
	}
	if(session->media.media_srtp_in) {
		JANUS_LOG(LOG_VERB, "%s inbound SRTP session created\n", "Media");
	}
	return 0;
}
static void janus_nosip_srtp_cleanup(janus_nosip_session *session) {
	if(session == NULL)
		return;
	session->media.autoack = TRUE;
	session->media.require_srtp = FALSE;
	session->media.has_srtp_local = FALSE;
	session->media.has_srtp_remote = FALSE;
	session->media.srtp_profile = 0;
//	/* Audio */
//	if( session->media.has_srtp_remote ) {
//		if(session->media.audio_srtp_out)
//			srtp_dealloc(session->media.audio_srtp_out);
//	}
//	session->media.audio_srtp_out = NULL;
//	g_free(session->media.audio_local_policy.key);
//	session->media.audio_local_policy.key = NULL;
//	if( session->media.has_srtp_local ) {
//		if(session->media.audio_srtp_in)
//			srtp_dealloc(session->media.audio_srtp_in);
//	}
//	session->media.audio_srtp_in = NULL;
//	g_free(session->media.audio_remote_policy.key);
//	session->media.audio_remote_policy.key = NULL;
	/* Media */
	if( session->media.has_srtp_remote ) {
		if(session->media.media_srtp_out)
			srtp_dealloc(session->media.media_srtp_out);
	}
	session->media.media_srtp_out = NULL;
	g_free(session->media.media_local_policy.key);
	session->media.media_local_policy.key = NULL;
	if( session->media.has_srtp_local ) {
		if(session->media.media_srtp_in)
			srtp_dealloc(session->media.media_srtp_in);
	}
	session->media.media_srtp_in = NULL;
	g_free(session->media.media_remote_policy.key);
	session->media.media_remote_policy.key = NULL;
}


/* SDP parsing and manipulation */
void janus_nosip_sdp_process(janus_nosip_session *session, janus_sdp *sdp, gboolean answer, gboolean update, gboolean *changed);
char *janus_nosip_sdp_manipulate(janus_nosip_session *session, janus_sdp *sdp, gboolean answer);
/* Media */
static int janus_nosip_allocate_local_ports(janus_nosip_session *session);
static void *janus_nosip_relay_thread(void *data);


/* Error codes */
#define JANUS_NOSIP_ERROR_UNKNOWN_ERROR			499
#define JANUS_NOSIP_ERROR_NO_MESSAGE			440
#define JANUS_NOSIP_ERROR_INVALID_JSON			441
#define JANUS_NOSIP_ERROR_INVALID_REQUEST		442
#define JANUS_NOSIP_ERROR_MISSING_ELEMENT		443
#define JANUS_NOSIP_ERROR_INVALID_ELEMENT		444
#define JANUS_NOSIP_ERROR_WRONG_STATE			445
#define JANUS_NOSIP_ERROR_MISSING_SDP			446
#define JANUS_NOSIP_ERROR_INVALID_SDP			447
#define JANUS_NOSIP_ERROR_IO_ERROR				448
#define JANUS_NOSIP_ERROR_RECORDING_ERROR		449
#define JANUS_NOSIP_ERROR_TOO_STRICT			450


/* Plugin implementation */
int janus_nosip_init(janus_callbacks *callback, const char *config_path) {
    if(g_atomic_int_get(&stopping)) {
        /* Still stopping from before */
        return -1;
    }
    if(callback == NULL || config_path == NULL) {
        /* Invalid arguments */
        return -1;
    }

    /* Read configuration */
    char filename[255];
    g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_NOSIP_PACKAGE);
    JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
    janus_config *config = janus_config_parse(filename);
    if(config == NULL) {
        JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_NOSIP_PACKAGE);
        g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_NOSIP_PACKAGE);
        JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
        config = janus_config_parse(filename);
    }
    if(config != NULL) {
        janus_config_print(config);

        janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
        janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "local_ip");
        if(item && item->value) {
            /* Verify that the address is valid */
            struct ifaddrs *ifas = NULL;
            janus_network_address iface;
            janus_network_address_string_buffer ibuf;
            if(getifaddrs(&ifas) == -1) {
                JANUS_LOG(LOG_ERR, "Unable to acquire list of network devices/interfaces; some configurations may not work as expected...\n");
            } else {
                if(janus_network_lookup_interface(ifas, item->value, &iface) != 0) {
                    JANUS_LOG(LOG_WARN, "Error setting local IP address to %s, falling back to detecting IP address...\n", item->value);
                } else {
                    if(janus_network_address_to_string_buffer(&iface, &ibuf) != 0 || janus_network_address_string_buffer_is_null(&ibuf)) {
                        JANUS_LOG(LOG_WARN, "Error getting local IP address from %s, falling back to detecting IP address...\n", item->value);
                    } else {
                        local_ip = g_strdup(janus_network_address_string_from_buffer(&ibuf));
                    }
                }
                freeifaddrs(ifas);
            }
        }

        item = janus_config_get(config, config_general, janus_config_type_item, "sdp_ip");
        if(item && item->value) {
            sdp_ip = g_strdup(item->value);
            JANUS_LOG(LOG_VERB, "IP to advertise in SDP: %s\n", sdp_ip);
        }

        item = janus_config_get(config, config_general, janus_config_type_item, "rtp_port_range");
        if(item && item->value) {
            /* Split in min and max port */
            char *maxport = strrchr(item->value, '-');
            if(maxport != NULL) {
                *maxport = '\0';
                maxport++;
                if(janus_string_to_uint16(item->value, &rtp_range_min) < 0)
                    JANUS_LOG(LOG_WARN, "Invalid RTP min port value: %s (assuming 0)\n", item->value);
                if(janus_string_to_uint16(maxport, &rtp_range_max) < 0)
                    JANUS_LOG(LOG_WARN, "Invalid RTP max port value: %s (assuming 0)\n", maxport);
                maxport--;
                *maxport = '-';
            }
            if(rtp_range_min > rtp_range_max) {
                uint16_t temp_port = rtp_range_min;
                rtp_range_min = rtp_range_max;
                rtp_range_max = temp_port;
            }
            if(rtp_range_min % 2)
                rtp_range_min++;    /* Pick an even port for RTP */
            if(rtp_range_min > rtp_range_max) {
                JANUS_LOG(LOG_WARN, "Incorrect port range (%u -- %u), switching min and max\n", rtp_range_min, rtp_range_max);
                uint16_t range_temp = rtp_range_max;
                rtp_range_max = rtp_range_min;
                rtp_range_min = range_temp;
            }
            if(rtp_range_max == 0)
                rtp_range_max = 65535;
            JANUS_LOG(LOG_VERB, "NoSIP RTP/RTCP port range: %u -- %u\n", rtp_range_min, rtp_range_max);
        }

        item = janus_config_get(config, config_general, janus_config_type_item, "events");
        if(item != NULL && item->value != NULL)
            notify_events = janus_is_true(item->value);
        if(!notify_events && callback->events_is_enabled()) {
            JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_NOSIP_NAME);
        }

        janus_config_destroy(config);
    }
    config = NULL;

    if(local_ip == NULL) {
        local_ip = janus_network_detect_local_ip_as_string(janus_network_query_options_any_ip);
        if(local_ip == NULL) {
            JANUS_LOG(LOG_WARN, "Couldn't find any address! using 127.0.0.1 as the local IP... (which is NOT going to work out of your machine)\n");
            local_ip = g_strdup("127.0.0.1");
        }
    }
    JANUS_LOG(LOG_VERB, "Local IP set to %s\n", local_ip);

#ifdef HAVE_SRTP_2
    /* Init randomizer (for randum numbers in SRTP) */
    RAND_poll();
#endif

    sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_nosip_session_destroy);
    messages = g_async_queue_new_full((GDestroyNotify) janus_nosip_message_free);
    /* This is the callback we'll need to invoke to contact the Janus core */
    gateway = callback;

    g_atomic_int_set(&initialized, 1);

    GError *error = NULL;
    /* Launch the thread that will handle incoming messages */
    handler_thread = g_thread_try_new("nosip handler", janus_nosip_handler, NULL, &error);
    if(error != NULL) {
        g_atomic_int_set(&initialized, 0);
        JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the NoSIP handler thread...\n", error->code, error->message ? error->message : "??");
        return -1;
    }
    JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_NOSIP_NAME);
    return 0;
}

void janus_nosip_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);

	g_free(local_ip);
	if(sdp_ip) {
		g_free(sdp_ip);
	}

	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_NOSIP_NAME);
}

int janus_nosip_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_nosip_get_version(void) {
	return JANUS_NOSIP_VERSION;
}

const char *janus_nosip_get_version_string(void) {
	return JANUS_NOSIP_VERSION_STRING;
}

const char *janus_nosip_get_description(void) {
	return JANUS_NOSIP_DESCRIPTION;
}

const char *janus_nosip_get_name(void) {
	return JANUS_NOSIP_NAME;
}

const char *janus_nosip_get_author(void) {
	return JANUS_NOSIP_AUTHOR;
}

const char *janus_nosip_get_package(void) {
	return JANUS_NOSIP_PACKAGE;
}

static janus_nosip_session *janus_nosip_lookup_session(janus_plugin_session *handle) {
	janus_nosip_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_nosip_session *)handle->plugin_handle;
	}
	return session;
}

void janus_nosip_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_nosip_session *session = g_malloc0(sizeof(janus_nosip_session));
	session->handle = handle;
	session->sdp = NULL;
	session->media.remote_ip = NULL;
	session->media.ready = 0;
	session->media.autoack = TRUE;
	session->media.require_srtp = FALSE;
	session->media.has_srtp_local = FALSE;
	session->media.has_srtp_remote = FALSE;
	session->media.srtp_profile = 0;
//	/* audio */
//	session->media.has_audio = 0;
//	session->media.audio_srtp_in = NULL;
//	session->media.audio_srtp_out = NULL;
//	session->media.audio_rtp_fd = -1;
//	session->media.audio_rtcp_fd = -1;
//	session->media.local_audio_rtp_port = 0;
//	session->media.remote_audio_rtp_port = 0;
//	session->media.local_audio_rtcp_port = 0;
//	session->media.remote_audio_rtcp_port = 0;
//	session->media.audio_ssrc = 0;
//	session->media.audio_ssrc_peer = 0;
//	session->media.audio_pt = -1;
//	session->media.audio_pt_name = NULL;
//	session->media.audio_send = TRUE;
	/* video */
	session->media.has_video = 0;
	session->media.media_recv_first = 0 ;
	session->media.media_rtp_fd = -1;
	session->media.media_srtp_in = NULL;
	session->media.media_srtp_out = NULL;
	session->media.local_media_rtp_port = 0;
	session->media.remote_media_rtp_port = 0;
//	session->media.local_media_rtcp_port = 0;
//	session->media.remote_media_rtcp_port = 0;
//	session->media.video_ssrc = 0;
//	session->media.video_ssrc_num = 0;
//	session->media.video_ssrc_peer = 0;
//	session->media.video_pt = -1;
//	session->media.video_pt_name = NULL;
//	session->media.media_send = TRUE;
//	session->media.media_recv = TRUE;
	/* data channel */
	session->media.has_application = 0;
//	session->media.local_application_port = 0;
//	session->media.remote_application_port = 0;
	session->media.application_pt = 0;
	session->media.application_pt_name = NULL;
//	session->media.application_fd = -1;
	/* Initialize the RTP context */
	janus_rtp_switching_context_reset(&session->media.context);
	session->media.pipefd[0] = -1;
	session->media.pipefd[1] = -1;
	session->media.updated = FALSE;

	session->remb_startup = 4;
	session->last_remb = 0;
	session->fir_seq = 0;
	session->last_fir = 0;

	janus_mutex_init(&session->rec_mutex);
	g_atomic_int_set(&session->destroyed, 0);
	g_atomic_int_set(&session->hangingup, 0);
	janus_mutex_init(&session->mutex);
	handle->plugin_handle = session;
	janus_refcount_init(&session->ref, janus_nosip_session_free);

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_nosip_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_nosip_session *session = janus_nosip_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No NoSIP session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_INFO, "[NoSIP-%p] Destroying NoSIP session (%p)...\n",session, session);
	janus_nosip_hangup_media_internal(handle);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_nosip_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_nosip_session *session = janus_nosip_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* Provide some generic info, e.g., if we're in a call and with whom */
	json_t *info = json_object();
	if(session->sdp) {
		json_object_set_new(info, "srtp-required", json_string(session->media.require_srtp ? "yes" : "no"));
		json_object_set_new(info, "sdes-local", json_string(session->media.has_srtp_local ? "yes" : "no"));
		json_object_set_new(info, "sdes-remote", json_string(session->media.has_srtp_remote ? "yes" : "no"));
	}
	if(session->mrc || session->mrc_peer) {
		json_t *recording = json_object();
		if(session->mrc && session->mrc->filename)
			json_object_set_new(recording, "media", json_string(session->mrc->filename));
		if(session->mrc_peer && session->mrc_peer->filename)
			json_object_set_new(recording, "media-peer", json_string(session->mrc_peer->filename));
		json_object_set_new(info, "recording", recording);
	}
	json_object_set_new(info, "hangingup", json_integer(g_atomic_int_get(&session->hangingup)));
	json_object_set_new(info, "destroyed", json_integer(g_atomic_int_get(&session->destroyed)));
	janus_refcount_decrease(&session->ref);
	return info;
}

struct janus_plugin_result *janus_nosip_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	janus_mutex_lock(&sessions_mutex);
	janus_nosip_session *session = janus_nosip_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	}

	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);

	janus_nosip_message *msg = g_malloc(sizeof(janus_nosip_message));
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->jsep = jsep;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
}

void janus_nosip_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_nosip_session *session = janus_nosip_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	g_atomic_int_set(&session->hangingup, 0);
	janus_mutex_unlock(&sessions_mutex);

//	if( session->media.has_application ) {
//		if(nosip_sctp_open_channel(session->sctp_association, 0, 0, 0) < 0) {
//			JANUS_LOG(LOG_ERR, "[NoSIP-%p] Couldn't open channel...\n", session);
//			return;
//		}
//		JANUS_LOG(LOG_INFO, "[NoSIP-%p] data channel is open\n", session);
//	}
}

void janus_nosip_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_nosip_session *session = (janus_nosip_session *)handle->plugin_handle;
		if(!session || g_atomic_int_get(&session->destroyed)) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		/* Forward to our NoSIP peer */
//		if((video && !session->media.media_send) || (!video && !session->media.audio_send)) {
//			/* Dropping packet, peer doesn't want to receive it */
//			return;
//		}
		gboolean video = packet->video;
		char *buf = packet->buffer;
		uint16_t len = packet->length;

		if (! session->media.media_recv_first) {
			rtp_header *header = (rtp_header *)buf;
			guint32 first_media_ssrc = ntohl(header->ssrc);
			JANUS_LOG(LOG_INFO, "[NoSIP-%p] incoming get packet with SSRC: %"SCNu32"\n",session,first_media_ssrc);
			session->media.media_recv_first = 1 ;
		}

//		if((video && session->media.video_ssrc == 0) || (!video && session->media.audio_ssrc == 0)) {
//			rtp_header *header = (rtp_header *)buf;
//			if(video) {
//				session->media.video_ssrc = ntohl(header->ssrc);
//			} else {
//				session->media.audio_ssrc = ntohl(header->ssrc);
//			}
//			JANUS_LOG(LOG_VERB, "[NoSIP-%p] incoming got NoSIP RTP %s SSRC: %"SCNu32"\n",session,
//				video ? "video" : "audio",
//				video ? session->media.video_ssrc : session->media.audio_ssrc);
//			if((video && session->media.media_recvonly) || (!video && session->media.audio_recvonly)) {
//				if(video) {
//					session->media.video_ssrc_peer = ntohl(header->ssrc);
//				} else {
//					session->media.audio_ssrc_peer = ntohl(header->ssrc);
//				}
//				JANUS_LOG(LOG_VERB, "[NoSIP-%p] incoming set with peer %s SSRC: %"SCNu32"\n",session,
//					video ? "video" : "audio",
//					video ? session->media.video_ssrc_peer : session->media.audio_ssrc_peer);
//			}
//		}

//		if( video && session->media.has_video ) {
////			send_remb(session);
////			send_reqfir(session);
//			int plen = 0;
//			char *payload = janus_rtp_payload(buf, len, &plen);
//			if(payload == NULL)
//				return;
//
//			if(janus_vp8_is_keyframe(payload, plen)) {
//				JANUS_LOG(LOG_VERB, "[NoSIP-%p] incoming IDR VP8\n",session);
//			}
//			if(janus_vp9_is_keyframe(payload, plen)) {
//				JANUS_LOG(LOG_VERB, "[NoSIP-%p] incoming IDR VP9\n",session);
//			}
//			if(janus_h264_is_keyframe(payload, plen)) {
//				JANUS_LOG(LOG_VERB, "[NoSIP-%p] incoming IDR H264\n",session);
//			}
//
//		}

		JANUS_LOG(LOG_HUGE, "[NoSIP-%p] incoming RTP ssrc %u \n",session,  ntohl(((rtp_header *)buf)->ssrc));
		if(session->media.has_video && session->media.media_rtp_fd != -1) {
			/* Save the frame if we're recording */
			janus_recorder_save_frame(session->mrc, buf, len);
			/* Is SRTP involved? */
			if(session->media.has_srtp_local) {
				char sbuf[2048];
				memcpy(&sbuf, buf, len);
				int protected = len;
				int res = srtp_protect( session->media.media_srtp_out, &sbuf, &protected);
				if(res != srtp_err_status_ok) {
					rtp_header *header = (rtp_header *)&sbuf;
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_ERR, "[NoSIP-%p] %s SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
						session, video ? "Video" : "Audio", janus_srtp_error_str(res), len, protected, timestamp, seq);
				} else {
					/* Forward the frame to the peer */
					if(send(session->media.media_rtp_fd, sbuf, protected, 0) < 0) {
						rtp_header *header = (rtp_header *)&sbuf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_WARN, "[NoSIP-%p] Error sending %s SRTP packet... %s (len=%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
							session, video ? "Video" : "Audio", strerror(errno), protected, timestamp, seq);
					}
				}
			} else {
				/* Forward the frame to the peer */
				if(send(session->media.media_rtp_fd, buf, len, 0) < 0) {
					rtp_header *header = (rtp_header *)&buf;
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_WARN, "[NoSIP-%p] Error sending %s RTP packet... %s (len=%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
						session, video ? "Video" : "Audio", strerror(errno), len, timestamp, seq);
				}
			}
		}
	}
}


void janus_nosip_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_nosip_session *session = (janus_nosip_session *)handle->plugin_handle;
		if(!session || g_atomic_int_get(&session->destroyed)) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		int fd = -1;
		fd = session->media.media_rtp_fd;
		
		gboolean video = packet->video;
		char *buf = packet->buffer;
		uint16_t len = packet->length;

//		if((video && session->media.video_recv) || (!video && session->media.audio_recv)) {
//			if((video && session->media.has_video && session->media.video_ssrc == 0) || (!video && session->media.has_audio && session->media.audio_ssrc == 0)) {
//				/* can happen when we sendonly */
//				guint32 rtcp_ssrc = janus_rtcp_get_sender_ssrc(buf, len);
//				JANUS_LOG(LOG_INFO, "[NoSIP-%p] Fixing %s SSRCs receiver peer not set, set it to %u (%u)\n",
//					session, video ? "video" : "audio", rtcp_ssrc, janus_rtcp_get_receiver_ssrc(buf, len));
//				if( video ) {
//					session->media.video_ssrc = rtcp_ssrc;
//				} else {
//					session->media.audio_ssrc = rtcp_ssrc;
//				}
//			}
//		}


//		if( video ) {
//			JANUS_LOG(LOG_HUGE, "[NoSIP-%p] incoming RTCP %s ssrc recvier %u sender %u\n",session,(video?"video":"audio"),janus_rtcp_get_receiver_ssrc(buf, len), janus_rtcp_get_sender_ssrc(buf, len));
//		}

		/* Forward to our NoSIP peer */
//		if(( video && session->media.has_video && (rtcp_mux || session->media.media_rtcp_fd != -1)) ||
//		   (!video && session->media.has_audio && (rtcp_mux || session->media.audio_rtcp_fd != -1)) ) {
			/* Fix SSRCs as the gateway does */

//			JANUS_LOG(LOG_HUGE, "[NoSIP-%p] Fixing %s SSRCs (local %u, peer %u)\n",
//				session, video ? "video" : "audio",
//				(video ? session->media.video_ssrc : session->media.audio_ssrc),
//				(video ? session->media.video_ssrc_peer : session->media.audio_ssrc_peer));
//			janus_rtcp_fix_ssrc(NULL, (char *)buf, len, video,
//				(video ? session->media.video_ssrc : session->media.audio_ssrc),
//				(video ? session->media.video_ssrc_peer : session->media.audio_ssrc_peer));
			/* Is SRTP involved? */
			if(session->media.has_srtp_local) {
				char sbuf[2048];
				memcpy(&sbuf, buf, len);
				int protected = len;
				int res = srtp_protect_rtcp(session->media.media_srtp_out, &sbuf, &protected);
				if(res != srtp_err_status_ok) {
					JANUS_LOG(LOG_ERR, "[NoSIP-%p] %s SRTCP protect error... %s (len=%d-->%d)...\n",
						session, video ? "Video" : "Audio",
						janus_srtp_error_str(res), len, protected);
				} else {
					/* Forward the message to the peer */
					if(send(fd, sbuf, protected, 0) < 0) {
						JANUS_LOG(LOG_HUGE, "[NoSIP-%p] Error sending SRTCP %s packet... %s (len=%d)...\n",
							session, video ? "Video" : "Audio", strerror(errno), protected);
					}
				}
			} else {
				/* Forward the message to the peer */
				if(send(fd, buf, len, 0) < 0) {
					JANUS_LOG(LOG_HUGE, "[NoSIP-%p] Error sending RTCP %s packet... %s (len=%d)...\n",
						session, video ? "Video" : "Audio", strerror(errno), len);
				}
			}
//		}
	}
}

void janus_nosip_hangup_media(janus_plugin_session *handle) {
	janus_mutex_lock(&sessions_mutex);
	janus_nosip_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

void janus_nosip_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_nosip_session *session = janus_nosip_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;

	char* buf = packet->buffer;
	int len = packet->length;

	JANUS_LOG(LOG_VERB, "[NoSIP-%p] receive sctp from janus %d\n", session, len);

	if(send(session->media.media_rtp_fd, buf, len, 0) < 0) {
		JANUS_LOG(LOG_WARN, "[NoSIP-%p] Error sending data packet... %s (len=%d)...\n",
			session, strerror(errno), len);
	}


//	g_async_queue_push(session->sctp_association->messages, nosip_sctp_message_create(TRUE, buf, len));
}

static void janus_nosip_hangup_media_internal(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_nosip_session *session = janus_nosip_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	JANUS_LOG(LOG_INFO, "[NoSIP-%p] No WebRTC media anymore\n", session);
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(g_atomic_int_add(&session->hangingup, 1))
		return;
	/* Notify the thread that it's time to go */
	JANUS_LOG(LOG_INFO, "[NoSIP-%p] Notify the relay thread that it's time to go\n", session);
	if(session->media.pipefd[1] > 0) {
		int code = 1;
		ssize_t res = 0;
		do {
			res = write(session->media.pipefd[1], &code, sizeof(int));
		} while(res == -1 && errno == EINTR);
	}
	/* Get rid of the recorders, if available */
	janus_mutex_lock(&session->rec_mutex);
	if(session->mrc) {
		janus_recorder_close(session->mrc);
		JANUS_LOG(LOG_INFO, "Closed user's media recording %s\n", session->mrc->filename ? session->mrc->filename : "??");
		janus_recorder_destroy(session->mrc);
	}
	session->mrc = NULL;
	if(session->mrc_peer) {
		janus_recorder_close(session->mrc_peer);
		JANUS_LOG(LOG_INFO, "Closed peer's media recording %s\n", session->mrc_peer->filename ? session->mrc_peer->filename : "??");
		janus_recorder_destroy(session->mrc_peer);
	}
	session->mrc_peer = NULL;
	janus_mutex_unlock(&session->rec_mutex);
}

/* Thread to handle incoming messages */
static void *janus_nosip_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining NoSIP handler thread\n");
	janus_nosip_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_nosip_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_nosip_session *session = janus_nosip_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_nosip_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_nosip_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_NOSIP_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_NOSIP_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_NOSIP_ERROR_MISSING_ELEMENT, JANUS_NOSIP_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *result = NULL, *localjsep = NULL;

		print_json("receive msg", root);
		if( msg->jsep )
			print_json("receive jsep", msg->jsep);

		if(!strcasecmp(request_text, "generate") || !strcasecmp(request_text, "process")) {
			/* Shared code for two different requests:	
			 * 		generate: Take a JSEP offer or answer and generate a barebone SDP the application can use
			 * 		process: Process a remote barebone SDP, and match it to the one we may have generated before */
			gboolean generate = !strcasecmp(request_text, "generate") ? TRUE : FALSE;
			if(generate) {
				JANUS_VALIDATE_JSON_OBJECT(root, generate_parameters,
					error_code, error_cause, TRUE,
					JANUS_NOSIP_ERROR_MISSING_ELEMENT, JANUS_NOSIP_ERROR_INVALID_ELEMENT);
			} else {
				JANUS_VALIDATE_JSON_OBJECT(root, process_parameters,
					error_code, error_cause, TRUE,
					JANUS_NOSIP_ERROR_MISSING_ELEMENT, JANUS_NOSIP_ERROR_INVALID_ELEMENT);
			}
			if(error_code != 0)
				goto error;
			/* Any SDP to handle? if not, something's wrong */
			const char *msg_sdp_type = json_string_value(json_object_get(generate ? msg->jsep : root, "type"));
			const char *msg_sdp = json_string_value(json_object_get(generate ? msg->jsep : root, "sdp"));
			gboolean sdp_update = json_is_true(json_object_get(generate ? msg->jsep : root, "update"));
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_NOSIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			if(!msg_sdp_type || (strcasecmp(msg_sdp_type, "offer") && strcasecmp(msg_sdp_type, "answer"))) {
				JANUS_LOG(LOG_ERR, "Missing or invalid SDP type\n");
				error_code = JANUS_NOSIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing or invalid SDP type");
				goto error;
			}
			gboolean offer = !strcasecmp(msg_sdp_type, "offer");
//			if(strstr(msg_sdp, "m=application")) {
//				JANUS_LOG(LOG_ERR, "The NoSIP plugin does not support DataChannels\n");
//				error_code = JANUS_NOSIP_ERROR_MISSING_SDP;
//				g_snprintf(error_cause, 512, "The NoSIP plugin does not support DataChannels");
//				goto error;
//			}
			/* Check if the user provided an info string to provide context */
			const char *info = json_string_value(json_object_get(root, "info"));
			/* SDES-SRTP is disabled by default, let's see if we need to enable it */
			gboolean do_srtp = FALSE, require_srtp = FALSE;
			janus_srtp_profile srtp_profile = JANUS_SRTP_AES128_CM_SHA1_80;
			if(generate) {
				json_t *srtp = json_object_get(root, "srtp");
				if(srtp) {
					const char *srtp_text = json_string_value(srtp);
					if(!strcasecmp(srtp_text, "sdes_optional")) {
						/* Negotiate SDES, but make it optional */
						do_srtp = TRUE;
					} else if(!strcasecmp(srtp_text, "sdes_mandatory")) {
						/* Negotiate SDES, and require it */
						do_srtp = TRUE;
						require_srtp = TRUE;
					} else {
						JANUS_LOG(LOG_ERR, "Invalid element (srtp can only be sdes_optional or sdes_mandatory)\n");
						error_code = JANUS_NOSIP_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid element (srtp can only be sdes_optional or sdes_mandatory)");
						goto error;
					}
					if(do_srtp) {
						/* Any SRTP profile different from the default? */
						srtp_profile = JANUS_SRTP_AES128_CM_SHA1_80;
						const char *profile = json_string_value(json_object_get(root, "srtp_profile"));
						if(profile) {
							if(!strcmp(profile, "AES_CM_128_HMAC_SHA1_32")) {
								srtp_profile = JANUS_SRTP_AES128_CM_SHA1_32;
							} else if(!strcmp(profile, "AES_CM_128_HMAC_SHA1_80")) {
								srtp_profile = JANUS_SRTP_AES128_CM_SHA1_80;
#ifdef HAVE_SRTP_AESGCM
							} else if(!strcmp(profile, "AEAD_AES_128_GCM")) {
								srtp_profile = JANUS_SRTP_AEAD_AES_128_GCM;
							} else if(!strcmp(profile, "AEAD_AES_256_GCM")) {
								srtp_profile = JANUS_SRTP_AEAD_AES_256_GCM;
#endif
							} else {
								JANUS_LOG(LOG_ERR, "Invalid element (unsupported SRTP profile)\n");
								error_code = JANUS_NOSIP_ERROR_INVALID_ELEMENT;
								g_snprintf(error_cause, 512, "Invalid element (unsupported SRTP profile)");
								goto error;
							}
						}
					}
				}
				if(!sdp_update) {
					if(offer) {
						/* Clean up SRTP stuff from before first, in case it's still needed */
						janus_nosip_srtp_cleanup(session);
						session->media.require_srtp = require_srtp;
						session->media.has_srtp_local = do_srtp;
						session->media.srtp_profile = srtp_profile;
						if(do_srtp) {
							JANUS_LOG(LOG_VERB, "Going to negotiate SDES-SRTP (%s)...\n", require_srtp ? "mandatory" : "optional");
						}
					} else {
						/* Make sure the request is consistent with the state (original offer) */
						if(session->media.require_srtp && !session->media.has_srtp_remote) {
							JANUS_LOG(LOG_ERR, "Can't generate answer: SDES-SRTP required, but caller didn't offer it\n");
							error_code = JANUS_NOSIP_ERROR_TOO_STRICT;
							g_snprintf(error_cause, 512, "Can't generate answer: SDES-SRTP required, but caller didn't offer it");
							goto error;
						}
						do_srtp = do_srtp || session->media.has_srtp_remote;
					}
				}
			}
			/* Parse the SDP we got, manipulate some things, and generate a new one */
			char sdperror[100];
			janus_sdp *parsed_sdp = janus_sdp_parse(msg_sdp, sdperror, sizeof(sdperror));
			if(!parsed_sdp) {
				JANUS_LOG(LOG_ERR, "Error parsing SDP: %s\n", sdperror);
				error_code = JANUS_NOSIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Error parsing SDP: %s", sdperror);
				goto error;
			}
			if(generate) {
				if(!sdp_update) {
					/* Allocate RTP ports and merge them with the anonymized SDP */
					if(strstr(msg_sdp, "m=audio") && !strstr(msg_sdp, "m=audio 0")) {
						JANUS_LOG(LOG_VERB, "Going to negotiate audio...\n");
						session->media.has_video = 1;	/* FIXME Maybe we need a better way to signal this */
					}
					if(strstr(msg_sdp, "m=video") && !strstr(msg_sdp, "m=video 0")) {
						JANUS_LOG(LOG_VERB, "Going to negotiate video...\n");
						session->media.has_video = 1;	/* FIXME Maybe we need a better way to signal this */
					}
					if(strstr(msg_sdp, "m=application") && !strstr(msg_sdp, "m=application 0")) {
						JANUS_LOG(LOG_VERB, "Going to negotiate data...\n");
						session->media.has_video = 1;	/* FIXME Maybe we need a better way to signal this */
					}
					if(janus_nosip_allocate_local_ports(session) < 0) {
						JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
						janus_sdp_destroy(parsed_sdp);
						error_code = JANUS_NOSIP_ERROR_IO_ERROR;
						g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
						goto error;
					}
				}
				char *sdp = janus_nosip_sdp_manipulate(session, parsed_sdp, FALSE);
				if(sdp == NULL) {
					JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
					janus_sdp_destroy(parsed_sdp);
					error_code = JANUS_NOSIP_ERROR_IO_ERROR;
					g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
					goto error;
				}
//				if( session->media.has_application ){
//					session->sctp_association = start_data_channel(session);
//					if( session->sctp_association == NULL ) {
//						JANUS_LOG(LOG_ERR, "Could not start data channel\n");
//						janus_sdp_destroy(parsed_sdp);
//						error_code = JANUS_NOSIP_ERROR_IO_ERROR;
//						g_snprintf(error_cause, 512, "Could not start data channel");
//						goto error;
//					}
//				}
				/* Take note of the SDP (may be useful for UPDATEs or re-INVITEs) */
				janus_sdp_destroy(session->sdp);
				session->sdp = parsed_sdp;
				JANUS_LOG(LOG_VERB, "Prepared SDP %s for (%p)\n%s", msg_sdp_type, info, sdp);
				g_atomic_int_set(&session->hangingup, 0);
				/* Also notify event handlers */
				if(!sdp_update && notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("generated"));
					json_object_set_new(info, "type", json_string(offer ? "offer" : "answer"));
					json_object_set_new(info, "sdp", json_string(sdp));
					gateway->notify_event(&janus_nosip_plugin, session->handle, info);
				}
				/* Send the barebone SDP back */
				result = json_object();
				json_object_set_new(result, "event", json_string("generated"));
				json_object_set_new(result, "type", json_string(offer ? "offer" : "answer"));
				json_object_set_new(result, "sdp", json_string(sdp));
				if(sdp_update)
					json_object_set_new(result, "update", json_true());
				g_free(sdp);
			} else {
				/* We got a barebone offer or answer from our peer: process it accordingly */
				gboolean changed = FALSE;
				if(!sdp_update && offer) {
					/* Clean up SRTP stuff from before first, in case it's still needed */
					janus_nosip_srtp_cleanup(session);
				}
				janus_nosip_sdp_process(session, parsed_sdp, !offer, sdp_update, &changed);
				/* Check if offer has neither audio nor video, fail */
				if( !session->media.has_video && !session->media.has_application) {
					JANUS_LOG(LOG_ERR, "No audio and no video being negotiated\n");
					janus_sdp_destroy(parsed_sdp);
					error_code = JANUS_NOSIP_ERROR_INVALID_SDP;
					g_snprintf(error_cause, 512, "No audio and no video and no data being negotiated");
					goto error;
				}
				/* Also fail if there's no remote IP address that can be used for RTP */
				if(!session->media.remote_ip) {
					JANUS_LOG(LOG_ERR, "No remote IP address\n");
					janus_sdp_destroy(parsed_sdp);
					error_code = JANUS_NOSIP_ERROR_INVALID_SDP;
					g_snprintf(error_cause, 512, "No remote IP address");
					goto error;
				}
				JANUS_LOG(LOG_INFO, "remote ip %s port: media- %d, data- %d\n",
						session->media.remote_ip, session->media.remote_media_rtp_port, session->media.remote_media_rtp_port);
				/* Take note of the SDP (may be useful for UPDATEs or re-INVITEs) */
				janus_sdp_destroy(session->sdp);
				session->sdp = parsed_sdp;
				/* Also notify event handlers */
				if(!sdp_update && notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("processed"));
					json_object_set_new(info, "type", json_string(offer ? "offer" : "answer"));
					json_object_set_new(info, "sdp", json_string(msg_sdp));
					gateway->notify_event(&janus_nosip_plugin, session->handle, info);
				}
				/* Send SDP to the browser */
				result = json_object();
				json_object_set_new(result, "event", json_string("processed"));
				if(session->media.has_srtp_remote) {
					json_object_set_new(result, "srtp",
						json_string(session->media.require_srtp ? "sdes_mandatory" : "sdes_optional"));
				}
				if(sdp_update)
					json_object_set_new(result, "update", json_true());
				localjsep = json_pack("{ssss}", "type", msg_sdp_type, "sdp", msg_sdp);
			}
			/* If this is an answer, start the media */
			if(!sdp_update && !offer) {
				/* Start the media */
				session->media.ready = 1;	/* FIXME Maybe we need a better way to signal this */
				GError *error = NULL;
				char tname[16];
				g_snprintf(tname, sizeof(tname), "nosiprtp %p", session);
				janus_refcount_increase(&session->ref);
				g_thread_try_new(tname, janus_nosip_relay_thread, session, &error);
				if(error != NULL) {
					janus_refcount_decrease(&session->ref);
					JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the RTP/RTCP thread...\n", error->code, error->message ? error->message : "??");
				}
			}
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Get rid of an ongoing session */
			gateway->close_pc(session->handle);
			result = json_object();
			json_object_set_new(result, "event", json_string("hangingup"));
			gateway->end_session(session->handle);
		} else if(!strcasecmp(request_text, "recording")) {
			/* Start or stop recording */
			JANUS_VALIDATE_JSON_OBJECT(root, recording_parameters,
				error_code, error_cause, TRUE,
				JANUS_NOSIP_ERROR_MISSING_ELEMENT, JANUS_NOSIP_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *action = json_object_get(root, "action");
			const char *action_text = json_string_value(action);
			if(strcasecmp(action_text, "start") && strcasecmp(action_text, "stop")) {
				JANUS_LOG(LOG_ERR, "Invalid action (should be start|stop)\n");
				error_code = JANUS_NOSIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid action (should be start|stop)");
				goto error;
			}
			gboolean record_media = FALSE, /* No media is recorded by default */
				record_peer_media = FALSE;
			json_t *audio = json_object_get(root, "audio");
			record_media = audio ? json_is_true(audio) : FALSE;
			json_t *video = json_object_get(root, "video");
			record_media = video ? json_is_true(video) : FALSE;
			json_t *peer_audio = json_object_get(root, "peer_audio");
			record_peer_media = peer_audio ? json_is_true(peer_audio) : FALSE;
			json_t *peer_video = json_object_get(root, "peer_video");
			record_peer_media = peer_video ? json_is_true(peer_video) : FALSE;
			if(!record_media && !record_peer_media) {
				JANUS_LOG(LOG_ERR, "Invalid request (at least one of audio, video, peer_audio and peer_video should be true)\n");
				error_code = JANUS_NOSIP_ERROR_RECORDING_ERROR;
				g_snprintf(error_cause, 512, "Invalid request (at least one of audio, video, peer_audio and peer_video should be true)");
				goto error;
			}
			json_t *recfile = json_object_get(root, "filename");
			const char *recording_base = json_string_value(recfile);
			janus_mutex_lock(&session->rec_mutex);
			if(!strcasecmp(action_text, "start")) {
				/* Start recording something */
				char filename[255];
				gint64 now = janus_get_real_time();
				if(record_peer_media ) {
					JANUS_LOG(LOG_INFO, "Starting recording of peer's record_peer_media\n");
					/* Start recording this peer's audio and/or video */
					/*if(record_peer_audio) */{
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-record_peer_media", recording_base);
							/* FIXME This only works if offer/answer happened */
							session->mrc_peer = janus_recorder_create(NULL, "opus", filename);
							if(session->mrc_peer == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an media peer recording file for this peer!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "nosip-%p-%"SCNi64"-peer-media", session, now);
							/* FIXME This only works if offer/answer happened */
							session->mrc_peer = janus_recorder_create(NULL, "opus", filename);
							if(session->mrc_peer == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an media peer recording file for this peer!\n");
							}
						}
					}
//					if(record_peer_video) {
//						memset(filename, 0, 255);
//						if(recording_base) {
//							/* Use the filename and path we have been provided */
//							g_snprintf(filename, 255, "%s-peer-video", recording_base);
//							/* FIXME This only works if offer/answer happened */
//							session->vrc_peer = janus_recorder_create(NULL, session->media.video_pt_name, filename);
//							if(session->vrc_peer == NULL) {
//								/* FIXME We should notify the fact the recorder could not be created */
//								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this peer!\n");
//							}
//						} else {
//							/* Build a filename */
//							g_snprintf(filename, 255, "nosip-%p-%"SCNi64"-peer-video", session, now);
//							/* FIXME This only works if offer/answer happened */
//							session->vrc_peer = janus_recorder_create(NULL, session->media.video_pt_name, filename);
//							if(session->vrc_peer == NULL) {
//								/* FIXME We should notify the fact the recorder could not be created */
//								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this peer!\n");
//							}
//						}
//						/* TODO We should send a FIR/PLI to this peer... */
//					}
				}
				if(record_media ) {
					/* Start recording the user's audio and/or video */
					JANUS_LOG(LOG_INFO, "Starting recording of user's media (%p)\n", session);
					/*if(record_audio)*/ {
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-user-audio", recording_base);
							/* FIXME This only works if offer/answer happened */
							session->mrc = janus_recorder_create(NULL, "opus", filename);
							if(session->mrc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an media recording file for this peer!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "nosip-%p-%"SCNi64"-own-audio", session, now);
							/* FIXME This only works if offer/answer happened */
							session->mrc = janus_recorder_create(NULL, "opus", filename);
							if(session->mrc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an media recording file for this peer!\n");
							}
						}
					}
//					if(record_video) {
//						memset(filename, 0, 255);
//						if(recording_base) {
//							/* Use the filename and path we have been provided */
//							g_snprintf(filename, 255, "%s-user-video", recording_base);
//							/* FIXME This only works if offer/answer happened */
//							session->vrc = janus_recorder_create(NULL, session->media.video_pt_name, filename);
//							if(session->vrc == NULL) {
//								/* FIXME We should notify the fact the recorder could not be created */
//								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this user!\n");
//							}
//						} else {
//							/* Build a filename */
//							g_snprintf(filename, 255, "nosip-%p-%"SCNi64"-own-video", session, now);
//							/* FIXME This only works if offer/answer happened */
//							session->vrc = janus_recorder_create(NULL, session->media.video_pt_name, filename);
//							if(session->vrc == NULL) {
//								/* FIXME We should notify the fact the recorder could not be created */
//								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this user!\n");
//							}
//						}
//						/* Send a PLI */
//						JANUS_LOG(LOG_VERB, "Recording video, sending a PLI to kickstart it\n");
//						char buf[12];
//						janus_rtcp_pli((char *)&buf, 12);
//						gateway->relay_rtcp(session->handle, 1, buf, 12);
//					}
				}
			} else {
				/* Stop recording something: notice that this never returns an error, even when we were not recording anything */
				if(record_media) {
					if(session->mrc) {
						janus_recorder_close(session->mrc);
						JANUS_LOG(LOG_INFO, "Closed user's media recording %s\n", session->mrc->filename ? session->mrc->filename : "??");
						janus_recorder_destroy(session->mrc);
					}
					session->mrc = NULL;
				}
//				if(record_video) {
//					if(session->vrc) {
//						janus_recorder_close(session->vrc);
//						JANUS_LOG(LOG_INFO, "Closed user's video recording %s\n", session->vrc->filename ? session->vrc->filename : "??");
//						janus_recorder_destroy(session->vrc);
//					}
//					session->vrc = NULL;
//				}
				if(record_peer_media) {
					if(session->mrc_peer) {
						janus_recorder_close(session->mrc_peer);
						JANUS_LOG(LOG_INFO, "Closed peer's media recording %s\n", session->mrc_peer->filename ? session->mrc_peer->filename : "??");
						janus_recorder_destroy(session->mrc_peer);
					}
					session->mrc_peer = NULL;
				}
//				if(record_peer_video) {
//					if(session->vrc_peer) {
//						janus_recorder_close(session->vrc_peer);
//						JANUS_LOG(LOG_INFO, "Closed peer's video recording %s\n", session->vrc_peer->filename ? session->vrc_peer->filename : "??");
//						janus_recorder_destroy(session->vrc_peer);
//					}
//					session->vrc_peer = NULL;
//				}
			}
			janus_mutex_unlock(&session->rec_mutex);
			/* Notify the result */
			result = json_object();
			json_object_set_new(result, "event", json_string("recordingupdated"));
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request (%s)\n", request_text);
			error_code = JANUS_NOSIP_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request (%s)", request_text);
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "nosip", json_string("event"));
		if(result != NULL)
			json_object_set_new(event, "result", result);

		print_json("send msg", event);
		if( localjsep )
			print_json("send jsep", localjsep);
		int ret = gateway->push_event(msg->handle, &janus_nosip_plugin, msg->transaction, event, localjsep);
		JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
		json_decref(event);
		if(localjsep)
			json_decref(localjsep);
		janus_nosip_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "nosip", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_nosip_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_nosip_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving NoSIP handler thread\n");
	return NULL;
}


void janus_nosip_sdp_process(janus_nosip_session *session, janus_sdp *sdp, gboolean answer, gboolean update, gboolean *changed) {
	if(!session || !sdp)
		return;
	/* c= */
	if(sdp->c_addr) {
		if(update && strcmp(sdp->c_addr, session->media.remote_ip)) {
			/* This is an update and an address changed */
			if(changed)
				*changed = TRUE;
		}
		g_free(session->media.remote_ip);
		session->media.remote_ip = g_strdup(sdp->c_addr);
	}
	GList *temp = sdp->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		session->media.require_srtp = session->media.require_srtp || (m->proto && !strcasecmp(m->proto, "RTP/SAVP"));
		if(m->type == JANUS_SDP_AUDIO) {
			if(m->port) {
				if(m->port != session->media.remote_media_rtp_port) {
					/* This is an update and an address changed */
					if(changed)
						*changed = TRUE;
				}
//				session->media.has_audio = 1;
				session->media.remote_media_rtp_port = m->port;
//				session->media.remote_media_rtp_port = m->port + !rtcp_mux;	/* FIXME We're assuming RTCP is on the next port */
//				if(m->direction == JANUS_SDP_SENDONLY || m->direction == JANUS_SDP_INACTIVE)
//					session->media.audio_send = FALSE;
//				else
//					session->media.audio_send = TRUE;
//				session->media.audio_sendonly = m->direction == JANUS_SDP_SENDONLY;
//
//				if(m->direction == JANUS_SDP_RECVONLY || m->direction == JANUS_SDP_INACTIVE)
//					session->media.audio_recv = FALSE;
//				else
//					session->media.audio_recv = TRUE;
//				session->media.audio_recvonly = m->direction == JANUS_SDP_RECVONLY;

			} else {
//				session->media.audio_send = FALSE;
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			if(m->port) {
				if(m->port != session->media.remote_media_rtp_port) {
					/* This is an update and an address changed */
					if(changed)
						*changed = TRUE;
				}
				session->media.has_video = 1;
				session->media.remote_media_rtp_port = m->port;
//				session->media.remote_media_rtcp_port = m->port + !rtcp_mux;	/* FIXME We're assuming RTCP is on the next port */
//				if(m->direction == JANUS_SDP_SENDONLY || m->direction == JANUS_SDP_INACTIVE)
//					session->media.media_send = FALSE;
//				else
//					session->media.media_send = TRUE;
//				session->media.media_sendonly = m->direction == JANUS_SDP_SENDONLY;
//
//				if(m->direction == JANUS_SDP_RECVONLY || m->direction == JANUS_SDP_INACTIVE)
//					session->media.media_recv = FALSE;
//				else
//					session->media.media_recv = TRUE;
//				session->media.media_recvonly = m->direction == JANUS_SDP_RECVONLY;
//
			} /*else {*/
//				session->media.media_send = FALSE;
//				session->media.media_recv = FALSE;
//			}
		} else if(m->type == JANUS_SDP_APPLICATION) {
			if(m->port) {
				if(m->port != session->media.remote_media_rtp_port) {
					/* This is an update and an address changed */
					if(changed)
						*changed = TRUE;
				}
				session->media.has_application = 1;
				session->media.remote_media_rtp_port = m->port;
			} else {
				session->media.has_application = 0;
			}
		} else {
			JANUS_LOG(LOG_WARN, "Unsupported media line (not audio/video)\n");
			temp = temp->next;
			continue;
		}
		if(m->c_addr) {
			if(update && strcmp(m->c_addr, session->media.remote_ip)) {
				/* This is an update and an address changed */
				if(changed)
					*changed = TRUE;
			}
			g_free(session->media.remote_ip);
			session->media.remote_ip = g_strdup(m->c_addr);
		}
		if(update) {
			/* FIXME This is a session update, we only accept changes in IP/ports */
			temp = temp->next;
			continue;
		}
		GList *tempA = m->attributes;
		GList *first = tempA;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			first = m->attributes;
			if(a->name) {
				if(!strcasecmp(a->name, "crypto")) {
					if(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) {
						gint32 tag = 0;
						char profile[101], crypto[101];
						/* FIXME inline can be more complex than that, and we're currently only offering SHA1_80 */
						int res = sscanf(a->value, "%"SCNi32" %100s inline:%100s",
							&tag, profile, crypto);
						if(res != 3) {
							JANUS_LOG(LOG_WARN, "Failed to parse crypto line, ignoring... %s\n", a->value);
						} else {
							gboolean video = (m->type == JANUS_SDP_VIDEO);
							janus_nosip_srtp_set_remote(session, video, profile, crypto);
							session->media.has_srtp_remote = TRUE;
						}
					}
				}
				if( rtcp_mux && (m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) ) {
					janus_sdp_attribute *mux = janus_sdp_attribute_create("rtcp-mux", NULL);
					m->attributes = g_list_insert_before(m->attributes, first, mux);
				}
			}
			tempA = tempA->next;
		}
//		if(answer && (m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO)) {
//			/* Check which codec was negotiated eventually */
//			int pt = -1;
//			if(m->ptypes)
//				pt = GPOINTER_TO_INT(m->ptypes->data);
//			if(pt > -1) {
//				if(m->type == JANUS_SDP_AUDIO) {
//					session->media.audio_pt = pt;
//				} else {
//					session->media.video_pt = pt;
//				}
//			}
//		}
		temp = temp->next;
	}
	if(update && changed && *changed) {
		/* Something changed: mark this on the session, so that the thread can update the sockets */
		session->media.updated = TRUE;
		if(session->media.pipefd[1] > 0) {
			int code = 1;
			ssize_t res = 0;
			do {
				res = write(session->media.pipefd[1], &code, sizeof(int));
			} while(res == -1 && errno == EINTR);
		}
	}
}

char *janus_nosip_sdp_manipulate(janus_nosip_session *session, janus_sdp *sdp, gboolean answer) {
	if(!session || !sdp)
		return NULL;
	/* Start replacing stuff */
	JANUS_LOG(LOG_VERB, "Setting protocol to %s\n", session->media.require_srtp ? "RTP/SAVP" : "RTP/AVP");
	GList *temp = sdp->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		GList *first = m->attributes;
		g_free(m->proto);
		if(m->type == JANUS_SDP_AUDIO) {
			m->proto = g_strdup(session->media.require_srtp ? "RTP/SAVP" : "RTP/AVP");
			m->port = session->media.local_media_rtp_port;
			if(session->media.has_srtp_local) {
				char *profile = NULL;
				char *crypto = NULL;
				janus_nosip_srtp_set_local(session, FALSE, &profile, &crypto);
				janus_sdp_attribute *a = janus_sdp_attribute_create("crypto", "1 %s inline:%s", profile, crypto);
				g_free(profile);
				g_free(crypto);
				m->attributes = g_list_append(m->attributes, a);
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			m->proto = g_strdup(session->media.require_srtp ? "RTP/SAVP" : "RTP/AVP");
			m->port = session->media.local_media_rtp_port;
			if(session->media.has_srtp_local) {
				char *profile = NULL;
				char *crypto = NULL;
				janus_nosip_srtp_set_local(session, TRUE, &profile, &crypto);
				janus_sdp_attribute *a = janus_sdp_attribute_create("crypto", "1 %s inline:%s", profile, crypto);
				g_free(profile);
				g_free(crypto);
				m->attributes = g_list_append(m->attributes, a);
			}
		} else if(m->type == JANUS_SDP_APPLICATION) {
			m->proto = g_strdup(session->media.require_srtp ? "DTLS/UDP" : "UDP");
			m->port = session->media.local_media_rtp_port;
			/* FIXME sctpmap and webrtc-datachannel should be dynamic */
			janus_sdp_attribute * a = janus_sdp_attribute_create("sctpmap", "5000 webrtc-datachannel 16");
			m->attributes = g_list_insert_before(m->attributes, first, a);

			if(session->media.has_srtp_local) {
				char *profile = NULL;
				char *crypto = NULL;
				janus_nosip_srtp_set_local(session, TRUE, &profile, &crypto);
				janus_sdp_attribute *a = janus_sdp_attribute_create("crypto", "1 %s inline:%s", profile, crypto);
				g_free(profile);
				g_free(crypto);
				m->attributes = g_list_append(m->attributes, a);
			}
		}
		g_free(m->c_addr);
		m->c_addr = sdp_ip ? g_strdup(sdp_ip) : g_strdup(local_ip);
//		if(answer && (m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO)) {
//			/* Check which codec was negotiated eventually */
//			int pt = -1;
//			if(m->ptypes)
//				pt = GPOINTER_TO_INT(m->ptypes->data);
//			if(pt > -1) {
//				if(m->type == JANUS_SDP_AUDIO) {
//					session->media.audio_pt = pt;
//				} else {
//					session->media.video_pt = pt;
//				}
//			}
//		}
		if( rtcp_mux && (m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) ) {
			janus_sdp_attribute *mux = janus_sdp_attribute_create("rtcp-mux", NULL);
			m->attributes = g_list_insert_before(m->attributes, m->attributes, mux);
		}
		temp = temp->next;
	}
	/* Generate a SDP string out of our changes */
	return janus_sdp_write(sdp);
}

//static uint16_t sctp_event_types[] = {
//	SCTP_ASSOC_CHANGE,
//	SCTP_PEER_ADDR_CHANGE,
//	SCTP_REMOTE_ERROR,
//	SCTP_SHUTDOWN_EVENT,
//	SCTP_ADAPTATION_INDICATION,
//	SCTP_SEND_FAILED_EVENT,
//	SCTP_STREAM_RESET_EVENT,
//	SCTP_STREAM_CHANGE_EVENT
//};
//
//
//janus_sctp_association * start_data_channel(janus_nosip_session *session){
//	if( session->media.has_application == 0 ) {
//		return NULL;
//	}
//
//	janus_sctp_association *sctp = g_malloc0(sizeof(janus_sctp_association));
//	janus_refcount_init(&sctp->ref, nosip_sctp_association_free);
//	g_atomic_int_set(&sctp->destroyed, 0);
////	sctp->dtls = dtls;
////	janus_refcount_increase(&((janus_dtls_srtp *)dtls)->ref);
//	sctp->handle_id = session->media.remote_application_port;
//	sctp->local_port = 5000;	/* FIXME We always use this one */
//	sctp->remote_port = 5000;
//	sctp->sock = NULL;
//
//	struct socket *sock = NULL;
//	unsigned int i = 0;
//	struct sockaddr_conn sconn;
//
//	/* Now go on with SCTP */
//	janus_sctp_channel *channel = NULL;
//
//	for(i = 0; i < NUMBER_OF_CHANNELS; i++) {
//		channel = &(sctp->channels[i]);
//		channel->id = i;
//		channel->state = DATA_CHANNEL_CLOSED;
//		channel->pr_policy = SCTP_PR_SCTP_NONE;
//		channel->pr_value = 0;
//		channel->stream = 0;
//		channel->unordered = 0;
//		channel->flags = 0;
//	}
//	for(i = 0; i < NUMBER_OF_STREAMS; i++) {
//		sctp->stream_channel[i] = NULL;
//		sctp->stream_buffer[i] = 0;
//	}
//	sctp->stream_buffer_counter = 0;
//	sctp->sock = NULL;
//	janus_mutex_init(&sctp->mutex);
//
//	usrsctp_register_address((void *)sctp);
//	usrsctp_sysctl_set_sctp_ecn_enable(0);
//	if((sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, nosip_sctp_incoming_data, NULL, 0, (void *)sctp)) == NULL) {
//		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error creating usrsctp socket... (%d)\n", sctp->handle_id, errno);
//		janus_refcount_decrease(&sctp->ref);
//		return NULL;
//	}
//	/* Set SO_LINGER */
//	struct linger linger_opt;
//	linger_opt.l_onoff = 1;
//	linger_opt.l_linger = 0;
//	if(usrsctp_setsockopt(sock, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt))) {
//		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SO_LINGER (%d)\n", sctp->handle_id, errno);
//		janus_refcount_decrease(&sctp->ref);
//		return NULL;
//	}
//	/* Allow resetting streams */
//	struct sctp_assoc_value av;
//	av.assoc_id = SCTP_ALL_ASSOC;
//	av.assoc_value = 1;
//	if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(struct sctp_assoc_value)) < 0) {
//		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_ENABLE_STREAM_RESET (%d)\n", sctp->handle_id, errno);
//		janus_refcount_decrease(&sctp->ref);
//		return NULL;
//	}
//	/* Disable Nagle */
//	uint32_t nodelay = 1;
//	if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay))) {
//		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_NODELAY (%d)\n", sctp->handle_id, errno);
//		janus_refcount_decrease(&sctp->ref);
//		return NULL;
//	}
//	/* Enable the events of interest */
//	struct sctp_event event;
//	memset(&event, 0, sizeof(event));
//	event.se_assoc_id = SCTP_ALL_ASSOC;
//	event.se_on = 1;
//	for(i = 0; i < sizeof(sctp_event_types)/sizeof(uint16_t); i++) {
//		event.se_type = sctp_event_types[i];
//		if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
//			JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_EVENT (%d)\n", sctp->handle_id, errno);
//			janus_refcount_decrease(&sctp->ref);
//			return NULL;
//		}
//	}
//	/* Configure our INIT message */
//	struct sctp_initmsg initmsg;
//	memset(&initmsg, 0, sizeof(struct sctp_initmsg));
//	initmsg.sinit_num_ostreams = 16;	/* What Firefox says in the INIT (Chrome says 1023) */
//	initmsg.sinit_max_instreams = 2048;	/* What both Chrome and Firefox say in the INIT */
//	if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg)) < 0) {
//		JANUS_LOG(LOG_ERR, "[%"SCNu64"] setsockopt error: SCTP_INITMSG (%d)\n", sctp->handle_id, errno);
//		janus_refcount_decrease(&sctp->ref);
//		return NULL;
//	}
//
//	memset(&sconn, 0, sizeof(struct sockaddr_conn));
//	sconn.sconn_family = AF_CONN;
//	sconn.sconn_port = htons(sctp->local_port);
//	sconn.sconn_addr = (void *)sctp;
//	if(usrsctp_bind(sock, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
//		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error binding client on port %"SCNu16" (%d)\n", sctp->handle_id, sctp->remote_port, errno);
//		janus_refcount_decrease(&sctp->ref);
//		return NULL;
//	}
//
//#ifdef DEBUG_SCTP
//	char debug_file[1024];
//	g_snprintf(debug_file, 1024, "%s/sctp-debug-%"SCNu64".txt", debug_folder, handle_id);
//	sctp->debug_dump = fopen(debug_file, "wt");
//#endif
//
//	/* We're done for now, the setup is done elsewhere */
//	janus_mutex_lock(&sctp->mutex);
//	sctp->sock = sock;
//	sctp->messages = g_async_queue_new_full((GDestroyNotify) nosip_sctp_message_destroy);
//	sctp->buffer = NULL;
//	sctp->buflen = 0;
//	sctp->offset = 0;
//	GError *error = NULL;
//	char tname[16];
//	g_snprintf(tname, sizeof(tname), "sctp %"SCNu64, sctp->handle_id);
//	janus_refcount_increase(&sctp->ref);
//	sctp->thread = g_thread_try_new(tname, &nosip_sctp_thread, session, &error);
//	if(error != NULL) {
//		/* Something went wrong... */
//		janus_mutex_unlock(&sctp->mutex);
//		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the SCTP thread...\n", sctp->handle_id, error->code, error->message ? error->message : "??");
//		janus_refcount_decrease(&sctp->ref);	/* This is for the failed thread */
//		janus_refcount_decrease(&sctp->ref);
//		return NULL;
//	}
//	janus_mutex_unlock(&sctp->mutex);
//
//	g_snprintf(tname, sizeof(tname), "sctp-connect %"SCNu64, sctp->handle_id);
//	janus_refcount_increase(&sctp->ref);
//	session->sctp_conn_thread = g_thread_try_new(tname, &nosip_sctp_association_setup, sctp, &error);
//	if(error != NULL) {
//		/* Something went wrong... */
//		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the SCTP thread...\n", sctp->handle_id, error->code, error->message ? error->message : "??");
//		janus_refcount_decrease(&sctp->ref);	/* This is for the failed thread */
//		janus_refcount_decrease(&sctp->ref);
//		return NULL;
//	}
//
//	return sctp;
//}

/* Bind local RTP/RTCP sockets */
static int janus_nosip_allocate_local_ports(janus_nosip_session *session) {
	if(session == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		return -1;
	}
	/* Reset status */
//	if(session->media.audio_rtp_fd != -1) {
//		close(session->media.audio_rtp_fd);
//		session->media.audio_rtp_fd = -1;
//	}
//	if(!rtcp_mux && session->media.audio_rtcp_fd != -1) {
//		close(session->media.audio_rtcp_fd);
//		session->media.audio_rtcp_fd = -1;
//	}
//	session->media.local_audio_rtp_port = 0;
//	session->media.local_audio_rtcp_port = 0;
//	session->media.audio_ssrc = 0;
	if(session->media.media_rtp_fd != -1) {
		close(session->media.media_rtp_fd);
		session->media.media_rtp_fd = -1;
	}
//	if(!rtcp_mux && session->media.media_rtcp_fd != -1) {
//		close(session->media.media_rtcp_fd);
//		session->media.media_rtcp_fd = -1;
//	}
//	if(session->media.application_fd != -1) {
//		close(session->media.application_fd);
//		session->media.application_fd = -1;
//	}
	session->media.local_media_rtp_port = 0;
//	session->media.local_media_rtcp_port = 0;
//	session->media.video_ssrc = 0;
	if(session->media.pipefd[0] > 0) {
		close(session->media.pipefd[0]);
		session->media.pipefd[0] = -1;
	}
	if(session->media.pipefd[1] > 0) {
		close(session->media.pipefd[1]);
		session->media.pipefd[1] = -1;
	}
	/* Start */
	int attempts = 100;	/* FIXME Don't retry forever */
//	if(session->media.has_audio) {
//		JANUS_LOG(LOG_VERB, "Allocating audio ports:\n");
//		struct sockaddr_in audio_rtp_address, audio_rtcp_address;
//		while(session->media.local_audio_rtp_port == 0 || (!rtcp_mux && session->media.local_audio_rtcp_port == 0)) {
//			if(attempts == 0)	/* Too many failures */
//				return -1;
//			if(session->media.audio_rtp_fd == -1) {
//				session->media.audio_rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
//			}
//			if(!rtcp_mux && session->media.audio_rtcp_fd == -1) {
//				session->media.audio_rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
//			}
//			if(session->media.audio_rtp_fd == -1 || (!rtcp_mux && session->media.audio_rtcp_fd == -1) ) {
//				JANUS_LOG(LOG_ERR, "Error creating audio sockets...\n");
//				return -1;
//			}
//			int rtp_port = g_random_int_range(rtp_range_min, rtp_range_max);
//			if(rtp_port % 2)
//				rtp_port++;	/* Pick an even port for RTP */
//			audio_rtp_address.sin_family = AF_INET;
//			audio_rtp_address.sin_port = htons(rtp_port);
//			inet_pton(AF_INET, local_ip, &audio_rtp_address.sin_addr.s_addr);
//			if(bind(session->media.audio_rtp_fd, (struct sockaddr *)(&audio_rtp_address), sizeof(struct sockaddr)) < 0) {
//				JANUS_LOG(LOG_ERR, "Bind failed for audio RTP (port %d), trying a different one...\n", rtp_port);
//				close(session->media.audio_rtp_fd);
//				session->media.audio_rtp_fd = -1;
//				attempts--;
//				continue;
//			}
//			JANUS_LOG(LOG_VERB, "Audio RTP listener bound to port %d\n", rtp_port);
//			if( !rtcp_mux ) {
//				int rtcp_port = rtp_port+1;
//				audio_rtcp_address.sin_family = AF_INET;
//				audio_rtcp_address.sin_port = htons(rtcp_port);
//				inet_pton(AF_INET, local_ip, &audio_rtcp_address.sin_addr.s_addr);
//				if(bind(session->media.audio_rtcp_fd, (struct sockaddr *)(&audio_rtcp_address), sizeof(struct sockaddr)) < 0) {
//					JANUS_LOG(LOG_ERR, "Bind failed for audio RTCP (port %d), trying a different one...\n", rtcp_port);
//					/* RTP socket is not valid anymore, reset it */
//					close(session->media.audio_rtp_fd);
//					session->media.audio_rtp_fd = -1;
//					close(session->media.audio_rtcp_fd);
//					session->media.audio_rtcp_fd = -1;
//					attempts--;
//					continue;
//				}
//				JANUS_LOG(LOG_VERB, "Audio RTCP listener bound to port %d\n", rtcp_port);
//				session->media.local_audio_rtcp_port = rtcp_port;
//			}
//			session->media.local_audio_rtp_port = rtp_port;
//
//		}
//	}
	if(session->media.has_video) {
		JANUS_LOG(LOG_VERB, "Allocating video ports:\n");
		struct sockaddr_in video_rtp_address ;
		while(session->media.local_media_rtp_port == 0 /*|| (!rtcp_mux && session->media.local_media_rtcp_port == 0)*/) {
			if(attempts == 0)	/* Too many failures */
				return -1;
			if(session->media.media_rtp_fd == -1) {
				session->media.media_rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
//			if(!rtcp_mux && session->media.media_rtcp_fd == -1) {
//				session->media.media_rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
//			}
			if(session->media.media_rtp_fd == -1 /*|| (!rtcp_mux && session->media.media_rtcp_fd == -1) */) {
				JANUS_LOG(LOG_ERR, "Error creating video sockets...\n");
				return -1;
			}
			int rtp_port = g_random_int_range(rtp_range_min, rtp_range_max);
			if(rtp_port % 2)
				rtp_port++;	/* Pick an even port for RTP */
			video_rtp_address.sin_family = AF_INET;
			video_rtp_address.sin_port = htons(rtp_port);
			inet_pton(AF_INET, local_ip, &video_rtp_address.sin_addr.s_addr);
			if(bind(session->media.media_rtp_fd, (struct sockaddr *)(&video_rtp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for video RTP (port %d), trying a different one...\n", rtp_port);
				close(session->media.media_rtp_fd);
				session->media.media_rtp_fd = -1;
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Media RTP listener bound to port %d\n", rtp_port);
//			if( !rtcp_mux ) {
//
//				int rtcp_port = rtp_port+1;
//				video_rtcp_address.sin_family = AF_INET;
//				video_rtcp_address.sin_port = htons(rtcp_port);
//				inet_pton(AF_INET, local_ip, &video_rtcp_address.sin_addr.s_addr);
//				if(bind(session->media.media_rtcp_fd, (struct sockaddr *)(&video_rtcp_address), sizeof(struct sockaddr)) < 0) {
//					JANUS_LOG(LOG_ERR, "Bind failed for video RTCP (port %d), trying a different one...\n", rtcp_port);
//					/* RTP socket is not valid anymore, reset it */
//					close(session->media.media_rtp_fd);
//					session->media.media_rtp_fd = -1;
//					close(session->media.media_rtcp_fd);
//					session->media.media_rtcp_fd = -1;
//					attempts--;
//					continue;
//				}
//				JANUS_LOG(LOG_VERB, "Video RTCP listener bound to port %d\n", rtcp_port);
//				session->media.local_media_rtcp_port = rtcp_port;
//			}
			session->media.local_media_rtp_port = rtp_port;
		}
	}
//	if(session->media.has_application) {
//		JANUS_LOG(LOG_VERB, "Allocating application ports:\n");
//		struct sockaddr_in application_rtp_address;
//		while(session->media.local_application_port == 0) {
//			if(attempts == 0)	/* Too many failures */
//				return -1;
//			if(session->media.application_fd == -1) {
//				session->media.application_fd = socket(AF_INET, SOCK_DGRAM, 0);
//			}
//
//			if(session->media.application_fd == -1 ) {
//				JANUS_LOG(LOG_ERR, "Error creating data sockets...\n");
//				return -1;
//			}
//			int rtp_port = g_random_int_range(rtp_range_min, rtp_range_max);
//			if(rtp_port % 2)
//				rtp_port++;	/* Pick an even port for RTP */
//			application_rtp_address.sin_family = AF_INET;
//			application_rtp_address.sin_port = htons(rtp_port);
//			inet_pton(AF_INET, local_ip, &application_rtp_address.sin_addr.s_addr);
//			if(bind(session->media.application_fd, (struct sockaddr *)(&application_rtp_address), sizeof(struct sockaddr)) < 0) {
//				JANUS_LOG(LOG_ERR, "Bind failed for data (port %d), trying a different one...\n", rtp_port);
//				close(session->media.application_fd);
//				session->media.application_fd = -1;
//				attempts--;
//				continue;
//			}
//			JANUS_LOG(LOG_VERB, "Application RTP listener bound to port %d\n", rtp_port);
//			session->media.local_application_port = rtp_port;
//		}
//	}


	/* We need this to quickly interrupt the poll when it's time to update a session or wrap up */
	pipe(session->media.pipefd);
	return 0;
}

/* Helper method to (re)connect RTP/RTCP sockets */
static void janus_nosip_connect_sockets(janus_nosip_session *session, struct sockaddr_in *server_addr) {
	if(!session || !server_addr)
		return;

	if(session->media.updated) {
		JANUS_LOG(LOG_INFO, "[NoSIP-%p] Updating session sockets\n", session);
	}

	/* Connect peers (FIXME This pretty much sucks right now) */
	if(session->media.remote_media_rtp_port) {
		server_addr->sin_port = htons(session->media.remote_media_rtp_port);
		if(connect(session->media.media_rtp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[NoSIP-%p] Couldn't connect media RTP? (%s:%d)\n", session, session->media.remote_ip, session->media.remote_media_rtp_port);
			JANUS_LOG(LOG_ERR, "[NoSIP-%p]   -- %d (%s)\n", session, errno, strerror(errno));
		}
	}
//	if(session->media.remote_application_port) {
//		server_addr->sin_port = htons(session->media.remote_application_port);
//		if(connect(session->media.application_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
//			JANUS_LOG(LOG_ERR, "[NoSIP-%p] Couldn't connect application? (%s:%d)\n", session, session->media.remote_ip, session->media.remote_application_port);
//			JANUS_LOG(LOG_ERR, "[NoSIP-%p]   -- %d (%s)\n", session, errno, strerror(errno));
//		}
//	}

}


#define    kRtcpExpectedVersion 2
#define    kRtcpMinHeaderLength 4
#define    kRtcpMinParseLength  8

#define    kRtpExpectedVersion 2
#define    kRtpMinParseLength 12

static gboolean is_rtcp(gchar *buffer, uint32_t length) {
	uint8_t *buf = (uint8_t *) buffer;

	if (length < kRtcpMinHeaderLength) {
		return FALSE;
	}

	const uint8_t V = buf[0] >> 6;
	if (V != kRtcpExpectedVersion) {
		return FALSE;
	}

	const uint8_t payloadType = buf[1];
	switch (payloadType) {
	case 192:
		return TRUE;
	case 193:
		// not supported
		// pass through and check for a potential RTP packet
		return FALSE;
	case 195:
	case 200:
	case 201:
	case 202:
	case 203:
	case 204:
	case 205:
	case 206:
	case 207:
		return TRUE;
	default:
		return FALSE;
	}
}
static gboolean is_rtp(gchar *buffer, uint32_t length) {
	uint8_t *buf = (uint8_t *) buffer;
	janus_rtp_header *header = (janus_rtp_header*) buf;

	if (length < kRtpMinParseLength) {
		return FALSE;
	}

	// Version
	const uint8_t V = buf[0] >> 6;
	if (V != kRtpExpectedVersion) {
		return FALSE;
	}

	uint32_t hlen = 12;
	if (header->csrccount) /* Skip CSRC if needed */
		hlen += header->csrccount * 4;
	if (hlen >= length) {
		return FALSE;
	}

	if (header->extension) {
		janus_rtp_header_extension *ext = (janus_rtp_header_extension*) (buf + hlen);
		if (ext) {
			uint16_t extlen = ntohs(ext->length) * 4;
			hlen += 4;
			if (length > (hlen + extlen))
				hlen += extlen;
			else {
				return FALSE;
			}
		}
	}
	return TRUE;
	//return ((header->type < 64) || (header->type >= 96));
}

static gboolean is_data(gchar *buf, uint32_t length) {
	gboolean rtcp = is_rtcp(buf, length);
	gboolean rtp = is_rtp(buf, length);
	return !rtcp && !rtp;
}



/* Thread to relay RTP/RTCP frames coming from the peer */
static void *janus_nosip_relay_thread(void *session_data) {
	janus_nosip_session *session = (janus_nosip_session *)session_data;
	if(!session) {
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_INFO, "[NoSIP-%p] Starting relay thread\n", session);

	gboolean have_server_ip = TRUE;
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	if(session->media.remote_ip == NULL) {
		JANUS_LOG(LOG_WARN, "[NoSIP-%p] No remote IP?\n", session);
	} else {
		if((inet_aton(session->media.remote_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->media.remote_ip);	/* ...resolve name */
			if(!host) {
				JANUS_LOG(LOG_ERR, "[NoSIP-%p] Couldn't get host (%s)\n", session, session->media.remote_ip);
				have_server_ip = FALSE;
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
	}
	if(have_server_ip) {
		janus_nosip_connect_sockets(session, &server_addr);
	}

	/* File descriptors */
	socklen_t addrlen;
	struct sockaddr_in remote;
	int resfd = 0, bytes = 0, pollerrs = 0;
	struct pollfd fds[6];
	int pipe_fd = session->media.pipefd[0];
	char buffer[65535];
	memset(buffer, 0, 65535);
	/* Loop */
	int num = 0;
	gboolean goon = TRUE;
//	int astep = 0, vstep = 0;
//	guint32 ats = 0, vts = 0;
	//session->media.last_rx_packet = ;
	while(goon && session != NULL &&
			!g_atomic_int_get(&session->destroyed) && !g_atomic_int_get(&session->hangingup)) {
		if(session->media.updated) {
			/* Apparently there was a session update */
			int is_addr_valid = inet_aton(session->media.remote_ip, &server_addr.sin_addr);
			if(have_server_ip && is_addr_valid != 0) {
				janus_nosip_connect_sockets(session, &server_addr);
			} else {
				JANUS_LOG(LOG_ERR, "[NoSIP-%p] Couldn't update session details: missing or invalid remote IP address? (%s)\n",
					session, session->media.remote_ip);
			}
			session->media.updated = FALSE;
		}

		/* Prepare poll */
		num = 0;
		if(session->media.media_rtp_fd != -1) {
			fds[num].fd = session->media.media_rtp_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
//		if(session->media.application_fd != -1) {
//			fds[num].fd = session->media.application_fd;
//			fds[num].events = POLLIN;
//			fds[num].revents = 0;
//			num++;
//		}
		if(pipe_fd != -1) {
			fds[num].fd = pipe_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
		/* Wait for some data */
		resfd = poll(fds, num, 1000);
		if(resfd < 0) {
			if(errno == EINTR) {
				JANUS_LOG(LOG_HUGE, "[NoSIP-%p] Got an EINTR (%s), ignoring...\n", session, strerror(errno));
				continue;
			}
			JANUS_LOG(LOG_ERR, "[NoSIP-%p] Error polling...\n", session);
			JANUS_LOG(LOG_ERR, "[NoSIP-%p]   -- %d (%s)\n", session, errno, strerror(errno));
			break;
		} else if(resfd == 0) {
			/* No data, keep going */
			continue;
		}
		if(session == NULL || g_atomic_int_get(&session->destroyed))
			break;
		int i = 0;
		for(i=0; i<num; i++) {
			if(fds[i].revents & (POLLERR | POLLHUP)) {
				/* If we just updated the session, let's wait until things have calmed down */
				if(session->media.updated)
					break;
				/* Check the socket error */
				int error = 0;
				socklen_t errlen = sizeof(error);
				getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
				if(error == 0) {
					/* Maybe not a breaking error after all? */
					continue;
				} else if(error == 111) {
//					/* ICMP error? If it's related to RTCP, let's just close the RTCP socket and move on */
//					if(!rtcp_mux && fds[i].fd == session->media.audio_rtcp_fd) {
//						JANUS_LOG(LOG_WARN, "[NoSIP-%p] Got a '%s' on the audio RTCP socket, closing it\n",
//							session, strerror(error));
//						close(session->media.audio_rtcp_fd);
//						session->media.audio_rtcp_fd = -1;
//					} else if(!rtcp_mux && fds[i].fd == session->media.media_rtcp_fd) {
//						JANUS_LOG(LOG_WARN, "[NoSIP-%p] Got a '%s' on the video RTCP socket, closing it\n",
//							session, strerror(error));
//						close(session->media.media_rtcp_fd);
//						session->media.media_rtcp_fd = -1;
//					}
				}
				/* FIXME Should we be more tolerant of ICMP errors on RTP sockets as well? */
				pollerrs++;
				if(pollerrs < 10000) {
					usleep(1000);
					continue;
				}
				JANUS_LOG(LOG_ERR, "[NoSIP-%p] Too many errors polling %d (socket #%d): %s...\n", session,
					fds[i].fd, i, fds[i].revents & POLLERR ? "POLLERR" : "POLLHUP");
				JANUS_LOG(LOG_ERR, "[NoSIP-%p]   -- %d (%s)\n", session, error, strerror(error));
				/* Can we assume it's pretty much over, after a POLLERR? */
				goon = FALSE;
				/* FIXME Close the PeerConnection */
				gateway->close_pc(session->handle);
				break;
			} else if(fds[i].revents & POLLIN) {
				if(pipe_fd != -1 && fds[i].fd == pipe_fd) {
					/* Poll interrupted for a reason, go on */
					int code = 0;
					(void)read(pipe_fd, &code, sizeof(int));
					break;
				}
				/* Got an RTP/RTCP packet */
				addrlen = sizeof(remote);
				bytes = recvfrom(fds[i].fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&remote, &addrlen);
				if(bytes < 0) {
					/* Failed to read? */
					continue;
				}
				/* Let's check what this is */
				gboolean media = (fds[i].fd == session->media.media_rtp_fd);
//				gboolean audio = (fds[i].fd == session->media.audio_rtp_fd || fds[i].fd == session->media.audio_rtcp_fd);
				gboolean data = FALSE;
				gboolean rtcp = FALSE;
				if( rtcp_mux )
					rtcp = is_rtcp(buffer, bytes);
//				else
//					rtcp = (fds[i].fd == session->media.audio_rtcp_fd || fds[i].fd == session->media.media_rtcp_fd);

//				if( video ) {
//					JANUS_LOG(LOG_HUGE, "[NoSIP-%p] %d relay %s %s (len=%d)...\n",session, fds[i].fd,(rtcp?"RTCP":"RTP"), (video?"video":"audio"), bytes);
//				}

				data = is_data(buffer, bytes);

				if(!rtcp && !data && (media) ) {
					/* Audio or Video RTP */
//					if((video && !session->media.media_recv) || (audio && !session->media.audio_recv)) {
//							/* Dropping packet, peer doesn't want to receive it */
//						JANUS_LOG(LOG_WARN, "[NoSIP-%p] %d relay dropping packet %s %s (len=%d)...\n",session, fds[i].fd,(rtcp?"RTCP":"RTP"), (video?"video":"audio"), bytes);
//						continue;
//					}

					pollerrs = 0;
					rtp_header *header = (rtp_header *)buffer;
//					if( media ) {
//						int plen = 0;
//						char *payload = janus_rtp_payload(buffer, bytes, &plen);
//						if(payload == NULL)
//							continue;
//
//						if(janus_vp8_is_keyframe(payload, plen)) {
//							JANUS_LOG(LOG_VERB, "[NoSIP-%p] relay IDR VP8\n",session);
//						}
//						if(janus_vp9_is_keyframe(payload, plen)) {
//							JANUS_LOG(LOG_VERB, "[NoSIP-%p] relay IDR VP9\n",session);
//						}
//						if(janus_h264_is_keyframe(payload, plen)) {
//							JANUS_LOG(LOG_VERB, "[NoSIP-%p] relay IDR H264\n",session);
//						}
//					}
//					if(( video && session->media.video_ssrc_peer != ntohl(header->ssrc)) ||
//					   ( audio && session->media.audio_ssrc_peer != ntohl(header->ssrc))) {
//						if(video) {
//							session->media.video_ssrc_peer = ntohl(header->ssrc);
//						} else {
//							session->media.audio_ssrc_peer = ntohl(header->ssrc);
//						}
//						JANUS_LOG(LOG_VERB, "[NoSIP-%p] relay got peer RTP %s SSRC: %"SCNu32"\n",
//							session, video ? "video" : "audio", video ? session->media.video_ssrc_peer : session->media.audio_ssrc_peer);
//						if((video && session->media.media_sendonly) || (audio && session->media.audio_sendonly)) {
//							if(video) {
//								session->media.video_ssrc = ntohl(header->ssrc);
//							} else {
//								session->media.audio_ssrc = ntohl(header->ssrc);
//							}
//							JANUS_LOG(LOG_VERB, "[NoSIP-%p] relay setting local to %s SSRC: %"SCNu32"\n",session,
//								video ? "video" : "audio",
//								video ? session->media.video_ssrc : session->media.audio_ssrc);
//						}
//					}
					/* Is this SRTP? */
					if(session->media.has_srtp_remote) {
						int buflen = bytes;
						srtp_err_status_t res = srtp_unprotect(session->media.media_srtp_in, buffer, &buflen);
						if(res != srtp_err_status_ok && res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
							guint32 timestamp = ntohl(header->timestamp);
							guint16 seq = ntohs(header->seq_number);
							JANUS_LOG(LOG_ERR, "[NoSIP-%p] %s SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n",
								session, "Media", janus_srtp_error_str(res), bytes, buflen, timestamp, seq);
							continue;
						}
						bytes = buflen;
					}
//					/* Check if the SSRC changed (e.g., after a re-INVITE or UPDATE) */
//					guint32 timestamp = ntohl(header->timestamp);
//					janus_rtp_header_update(header, &session->media.context, video,
//						(video ? (vstep ? vstep : 4500) : (astep ? astep : 960)));
//					if(video) {
//						if(vts == 0) {
//							vts = timestamp;
//						} else if(vstep == 0) {
//							vstep = timestamp-vts;
//							if(vstep < 0) {
//								vstep = 0;
//							}
//						}
//					} else if( audio ) {
//						if(ats == 0) {
//							ats = timestamp;
//						} else if(astep == 0) {
//							astep = timestamp-ats;
//							if(astep < 0) {
//								astep = 0;
//							}
//						}
//					}
					/* Save the frame if we're recording */
					janus_recorder_save_frame( session->mrc_peer, buffer, bytes);
					/* Relay to browser */
					JANUS_LOG(LOG_HUGE, "[NoSIP-%p] %d relay RTP %s ssrc %u len %d\n",session, fds[i].fd, "media", ntohl(header->ssrc), bytes);
					janus_plugin_rtp rtp = { .buffer = buffer, .length = bytes };
					janus_plugin_rtp_extensions_reset(&rtp.extensions);
					gateway->relay_rtp(session->handle, &rtp);
					continue;
				} else if ( rtcp && (media) ){
					/* Audio or Video RTCP */
					if(session->media.has_srtp_remote) {
						int buflen = bytes;
						srtp_err_status_t res = srtp_unprotect_rtcp(session->media.media_srtp_in, buffer, &buflen);
						if(res != srtp_err_status_ok && res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
							JANUS_LOG(LOG_ERR, "[NoSIP-%p] %s SRTCP unprotect error: %s (len=%d-->%d)\n",
								session, "media", janus_srtp_error_str(res), bytes, buflen);
							continue;
						}
						bytes = buflen;
					}
//					if( video ) {
//						JANUS_LOG(LOG_HUGE, "[NoSIP-%p] relay RTCP %s ssrc recvier %u sender %u\n",session,(video?"video":"audio"),janus_rtcp_get_receiver_ssrc(buffer, bytes), janus_rtcp_get_sender_ssrc(buffer, bytes));
//					}

//					if((video && session->media.video_recv) || (audio && session->media.audio_recv)) {
//						guint32 rtcp_ssrc = janus_rtcp_get_sender_ssrc(buffer, bytes);
//						if( ( video && rtcp_ssrc && session->media.video_ssrc_peer == 0 && session->media.video_ssrc_peer != rtcp_ssrc  ) ||
//							( audio && rtcp_ssrc && session->media.audio_ssrc_peer == 0 && session->media.audio_ssrc_peer != rtcp_ssrc  )  ) {
//							/* can happen when we recvonly */
//							JANUS_LOG(LOG_INFO, "[NoSIP-%p] Fixing %s SSRCs sender peer not set, set it to %u (%u)\n",
//								session, video ? "video" : "audio", rtcp_ssrc, janus_rtcp_get_receiver_ssrc(buffer, bytes));
//							if( video ) {
//								session->media.video_ssrc_peer = rtcp_ssrc;
//							} else {
//								session->media.audio_ssrc_peer = rtcp_ssrc;
//							}
//						}
//					}
					int need_to_send = 1;
//					if( janus_rtcp_has_fir( buffer, bytes) ) {
//						need_to_send = 1;
//						JANUS_LOG(LOG_HUGE, "[NoSIP-%p] relay FIR\n", session);
//					} else if( janus_rtcp_has_pli( buffer, bytes)) {
//						need_to_send = 1;
//						JANUS_LOG(LOG_HUGE, "[NoSIP-%p] relay PLI\n", session);
//					} else if( janus_rtcp_get_remb( buffer, bytes) ) {
//						need_to_send = 1;
//						JANUS_LOG(LOG_HUGE, "[NoSIP-%p] relay REMB\n", session);
//					} else {
//						JANUS_LOG(LOG_HUGE, "[NoSIP-%p] unnown\n", session);
//						need_to_send = 0;
//					}

					char *rtcp_buf = buffer;
					int rtcp_len = bytes;
//					rtcp_buf = janus_rtcp_filter(buffer, bytes, &rtcp_len);
//					if(rtcp_buf == NULL || rtcp_len < 1)
//						continue;

					/* Relay to browser */
					JANUS_LOG(LOG_HUGE, "[NoSIP-%p] %d relay RTCP len %d\n",session, fds[i].fd, bytes);
					janus_plugin_rtcp rtcp = { .buffer = buffer, bytes };
					gateway->relay_rtcp(session->handle, &rtcp);

					if(rtcp_buf != buffer) {
						/* We filtered the original packet, deallocate it */
						JANUS_LOG(LOG_HUGE, "[NoSIP-%p] fillter has been used %d\n", session, need_to_send);
						g_free(rtcp_buf);
					}
					continue;
				} else if ( data & (media) ) {
					// data
					JANUS_LOG(LOG_INFO, "[NoSIP-%p] receive data %d\n", session, bytes);
					janus_plugin_data data = { .label = NULL, .buffer = buffer, .length = bytes };
					gateway->relay_data(session->handle, &data);
				} else {
				    JANUS_LOG(LOG_ERR, "[NoSIP-%p] cannot classified data %d\n", session, bytes);
				}
			}
		}
	}
//	if(session->media.audio_rtp_fd != -1) {
//		close(session->media.audio_rtp_fd);
//		session->media.audio_rtp_fd = -1;
//	}
//	if(!rtcp_mux && session->media.audio_rtcp_fd != -1) {
//		close(session->media.audio_rtcp_fd);
//		session->media.audio_rtcp_fd = -1;
//	}
//	session->media.local_audio_rtp_port = 0;
//	session->media.local_audio_rtcp_port = 0;
//	session->media.audio_ssrc = 0;
	if(session->media.media_rtp_fd != -1) {
		close(session->media.media_rtp_fd);
		session->media.media_rtp_fd = -1;
	}
//	if(!rtcp_mux && session->media.media_rtcp_fd != -1) {
//		close(session->media.media_rtcp_fd);
//		session->media.media_rtcp_fd = -1;
//	}
	session->media.local_media_rtp_port = 0;
//	session->media.local_media_rtcp_port = 0;
//	session->media.video_ssrc = 0;
//	if(session->media.application_fd != -1) {
//		close(session->media.application_fd);
//		session->media.application_fd = -1;
//	}
//	nosip_sctp_association_destroy(session->sctp_association);
//	session->media.local_application_port = 0;
	if(session->media.pipefd[0] > 0) {
		close(session->media.pipefd[0]);
		session->media.pipefd[0] = -1;
	}
	if(session->media.pipefd[1] > 0) {
		close(session->media.pipefd[1]);
		session->media.pipefd[1] = -1;
	}
	/* Clean up SRTP stuff, if needed */
	janus_nosip_srtp_cleanup(session);
	/* Done */
	JANUS_LOG(LOG_INFO, "[NoSIP-%p] Leaving NoSIP relay thread\n", session);
	janus_refcount_decrease(&session->ref);
	g_thread_unref(g_thread_self());
	return NULL;
}
