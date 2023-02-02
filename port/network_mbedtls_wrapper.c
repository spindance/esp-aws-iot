#include <sys/param.h>
#include <stdbool.h>
#include <string.h>

#include <log.h>

#include "network_mbedtls_wrapper.h"
#include "mbedtls/esp_debug.h"

#ifdef CONFIG_AWS_IOT_USE_HARDWARE_SECURE_ELEMENT
#include "mbedtls/atca_mbedtls_wrap.h"
#include "tng_atca.h"
#include "tng_atcacert_client.h"
#endif

#define TAG "network_mbedtls_wrapper"

static int random_number_generator(void* p_rng, unsigned char* buf, size_t len) {
    (void)p_rng;

    assert(buf != NULL);

    uint8_t *buf_bytes = (uint8_t *)buf;
    size_t length = len;

    while (length > 0) {
        int word = rand();
        size_t to_copy = (size_t)MIN(sizeof(word), length);
        memcpy(buf_bytes, &word, to_copy);
        buf_bytes += to_copy;
        length -= to_copy;
    }

    return 0;
}

/*
 * This is a function to do further verification if needed on the cert received.
 *
 * Currently used to print debug-level information about each cert.
 */
static int _verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    char buf[256];
    ((void) data);

    log_trace(TAG, "Verify requested for (Depth %d):", depth);
    mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
    log_trace(TAG, "%s", buf);

    if((*flags) == 0) {
        log_trace(TAG, "  This certificate has no flags");
    } else {
        log_trace(TAG, "Verify result:%s", buf);
    }

    return 0;
}

static void _set_connect_params(
        NetworkContext_t *pNetwork,
        const char *pRootCALocation,
        const char *pDeviceCertLocation,
        const char *pDevicePrivateKeyLocation,
        const char *pDestinationURL,
        uint16_t destinationPort,
        uint32_t timeout_ms,
        bool ServerVerificationFlag) {
    pNetwork->tlsConnectParams.DestinationPort = destinationPort;
    pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
    pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
    pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
    pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
    pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
    pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
}

MbedtlsStatus_t Mbedtls_Init(
        NetworkContext_t *pNetwork,
        const char *pRootCALocation,
        const char *pDeviceCertLocation,
        const char *pDevicePrivateKeyLocation,
        const char *pDestinationURL,
        uint16_t destinationPort,
        uint32_t timeout_ms,
        bool ServerVerificationFlag) {
    _set_connect_params(
            pNetwork,
            pRootCALocation,
            pDeviceCertLocation,
            pDevicePrivateKeyLocation,
            pDestinationURL,
            destinationPort,
            timeout_ms,
            ServerVerificationFlag);
    pNetwork->tlsDataParams.flags = 0;
    return MBEDTLS_SUCCESS;
}

static void _tls_destroy(const NetworkContext_t *pNetwork) {
    TLSDataParams *tlsDataParams = (TLSDataParams*)(&(pNetwork->tlsDataParams));
    mbedtls_net_free(&(tlsDataParams->server_fd));
    mbedtls_x509_crt_free(&(tlsDataParams->clicert));
    mbedtls_x509_crt_free(&(tlsDataParams->cacert));
    mbedtls_pk_free(&(tlsDataParams->pkey));
    mbedtls_ssl_free(&(tlsDataParams->ssl));
    mbedtls_ssl_config_free(&(tlsDataParams->conf));
    mbedtls_ctr_drbg_free(&(tlsDataParams->ctr_drbg));
    mbedtls_entropy_free(&(tlsDataParams->entropy));
}


MbedtlsStatus_t Mbedtls_Connect( NetworkContext_t * pNetwork, TLSConnectParams* params) {
    int ret = MBEDTLS_SUCCESS;
    TLSDataParams *tlsDataParams = NULL;
    char portBuffer[6];
    char info_buf[256];

    if(NULL == pNetwork) {
        return MBEDTLS_NULL_VALUE_ERROR;
    }

    if(NULL != params) {
        _set_connect_params(
                pNetwork,
                params->pRootCALocation,
                params->pDeviceCertLocation,
                params->pDevicePrivateKeyLocation,
                params->pDestinationURL,
                params->DestinationPort,
                params->timeout_ms,
                params->ServerVerificationFlag);
    }

    tlsDataParams = &(pNetwork->tlsDataParams);

    mbedtls_net_init(&(tlsDataParams->server_fd));
    mbedtls_ssl_init(&(tlsDataParams->ssl));
    mbedtls_ssl_config_init(&(tlsDataParams->conf));

#ifdef CONFIG_MBEDTLS_DEBUG
    log_warn(TAG, "Enable mbedtls debug logging");
    mbedtls_esp_enable_debug_log(&(tlsDataParams->conf), 1);
#endif

    mbedtls_ctr_drbg_init(&(tlsDataParams->ctr_drbg));
    mbedtls_x509_crt_init(&(tlsDataParams->cacert));
    mbedtls_x509_crt_init(&(tlsDataParams->clicert));
    mbedtls_pk_init(&(tlsDataParams->pkey));

    log_trace(TAG, "Seeding the random number generator...");
    mbedtls_entropy_init(&(tlsDataParams->entropy));
    if((ret = mbedtls_ctr_drbg_seed(&(tlsDataParams->ctr_drbg), mbedtls_entropy_func, &(tlsDataParams->entropy), NULL, 0)) != 0) {
        log_error(TAG, "failed! mbedtls_ctr_drbg_seed returned -0x%x", -ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_ENTROPY_SOURCE_FAILED;
    }

   /*  Load root CA...

       Certs/keys can be paths or they can be raw data. These use a
       very basic heuristic: if the cert starts with '/' then it's a
       path, if it's longer than this then it's raw cert data (PEM or DER,
       neither of which can start with a slash. */
    if (pNetwork->tlsConnectParams.pRootCALocation[0] == '/') {
        log_trace(TAG, "Loading CA root certificate from file ...");
        ret = mbedtls_x509_crt_parse_file(&(tlsDataParams->cacert), pNetwork->tlsConnectParams.pRootCALocation);
    } else {
        log_trace(TAG, "Loading embedded CA root certificate ...");
        ret = mbedtls_x509_crt_parse(&(tlsDataParams->cacert), (const unsigned char *)pNetwork->tlsConnectParams.pRootCALocation,
                                 strlen(pNetwork->tlsConnectParams.pRootCALocation)+1);
    }

    if(ret < 0) {
        log_error(TAG, "failed!  mbedtls_x509_crt_parse returned -0x%x while parsing root cert", -ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_ROOT_CRT_PARSE_ERROR;
    }
    log_trace(TAG, "ok (%d skipped)", ret);

    /* Load client certificate... */
#ifdef CONFIG_AWS_IOT_USE_HARDWARE_SECURE_ELEMENT
    if (pNetwork->tlsConnectParams.pDeviceCertLocation[0] == '#') {
        const atcacert_def_t* cert_def = NULL;
        log_trace(TAG, "Using certificate stored in ATECC608A");
        ret = tng_get_device_cert_def(&cert_def);
        if (ret == 0) {
            ret = atca_mbedtls_cert_add(&(tlsDataParams->clicert), cert_def);
        } else {
            log_error(TAG, "failed! could not load cert from ATECC608A, tng_get_device_cert_def returned %02x", ret);
        }
    } else
#endif
    if (pNetwork->tlsConnectParams.pDeviceCertLocation[0] == '/') {
        log_trace(TAG, "Loading client cert from file...");
        ret = mbedtls_x509_crt_parse_file(&(tlsDataParams->clicert),
                                          pNetwork->tlsConnectParams.pDeviceCertLocation);
    } else {
        log_trace(TAG, "Loading embedded client certificate...");
        ret = mbedtls_x509_crt_parse(&(tlsDataParams->clicert),
                                     (const unsigned char *)pNetwork->tlsConnectParams.pDeviceCertLocation,
                                     strlen(pNetwork->tlsConnectParams.pDeviceCertLocation)+1);
    }
    if(ret != 0) {
        log_error(TAG, "failed!  mbedtls_x509_crt_parse returned -0x%x while parsing device cert", -ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_DEVICE_CRT_PARSE_ERROR;
    }

    /* Parse client private key... */
#ifdef CONFIG_AWS_IOT_USE_HARDWARE_SECURE_ELEMENT
    if (pNetwork->tlsConnectParams.pDevicePrivateKeyLocation[0] == '#') {
        int8_t slot_id = pNetwork->tlsConnectParams.pDevicePrivateKeyLocation[1] - '0';
        if (slot_id < 0 || slot_id > 9) {
            log_error(TAG, "Invalid ATECC608A slot ID.");
            ret = NETWORK_PK_PRIVATE_KEY_PARSE_ERROR;
        } else {
            log_trace(TAG, "Using ATECC608A private key from slot %d", slot_id);
            ret = atca_mbedtls_pk_init(&(tlsDataParams->pkey), slot_id);
            if (ret != 0) {
                log_error(TAG, "failed !  atca_mbedtls_pk_init returned %02x", ret);
            }
        }
    } else
#endif
    if (pNetwork->tlsConnectParams.pDevicePrivateKeyLocation[0] == '/') {
        log_trace(TAG, "Loading client private key from file...");
        ret = mbedtls_pk_parse_keyfile(&(tlsDataParams->pkey),
                                       pNetwork->tlsConnectParams.pDevicePrivateKeyLocation,
                                       "",
                                       random_number_generator,
                                       NULL);
    } else {
        log_trace(TAG, "Loading embedded client private key...");
        ret = mbedtls_pk_parse_key(&(tlsDataParams->pkey),
                                   (const unsigned char *)pNetwork->tlsConnectParams.pDevicePrivateKeyLocation,
                                   strlen(pNetwork->tlsConnectParams.pDevicePrivateKeyLocation)+1,
                                   (const unsigned char *)"",
                                   0,
                                   random_number_generator,
                                   NULL);
    }
    if(ret != 0) {
        log_error(TAG, "failed!  mbedtls_pk_parse_key returned -0x%x while parsing private key", -ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_PRIVATE_KEY_PARSE_ERROR;
    }

    /* Done parsing certs */
    log_trace(TAG, "ok");
    snprintf(portBuffer, 6, "%d", pNetwork->tlsConnectParams.DestinationPort);
    log_trace(TAG, "Connecting to %s/%s...", pNetwork->tlsConnectParams.pDestinationURL, portBuffer);
    if((ret = mbedtls_net_connect(&(tlsDataParams->server_fd), pNetwork->tlsConnectParams.pDestinationURL,
                                  portBuffer, MBEDTLS_NET_PROTO_TCP)) != 0) {
        log_error(TAG, "failed! mbedtls_net_connect returned -0x%x", -ret);
        switch(ret) {
            case MBEDTLS_ERR_NET_SOCKET_FAILED:
                ret = MBEDTLS_SOCKET_FAILED;
                break;
            case MBEDTLS_ERR_NET_UNKNOWN_HOST:
                ret = MBEDTLS_UNKNOWN_HOST;
                break;
            case MBEDTLS_ERR_NET_CONNECT_FAILED:
            default:
                ret = MBEDTLS_CONNECT_FAILED;
        }
        _tls_destroy(pNetwork);
        return ret;
    }

    ret = mbedtls_net_set_block(&(tlsDataParams->server_fd));
    if(ret != 0) {
        log_error(TAG, "failed! net_set_(non)block() returned -0x%x", -ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_SSL_CONNECTION_ERROR;
    } log_trace(TAG, "ok");

    log_trace(TAG, "Setting up the SSL/TLS structure...");
    if((ret = mbedtls_ssl_config_defaults(&(tlsDataParams->conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        log_error(TAG, "failed! mbedtls_ssl_config_defaults returned -0x%x", -ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_SSL_CONNECTION_ERROR;
    }

    mbedtls_ssl_conf_verify(&(tlsDataParams->conf), _verify_cert, NULL);

    if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
        mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_REQUIRED);
    } else {
        mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    mbedtls_ssl_conf_rng(&(tlsDataParams->conf), mbedtls_ctr_drbg_random, &(tlsDataParams->ctr_drbg));

    mbedtls_ssl_conf_ca_chain(&(tlsDataParams->conf), &(tlsDataParams->cacert), NULL);
    ret = mbedtls_ssl_conf_own_cert(&(tlsDataParams->conf), &(tlsDataParams->clicert), &(tlsDataParams->pkey));
    if(ret != 0) {
        log_error(TAG, "failed! mbedtls_ssl_conf_own_cert returned %d", ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_SSL_CONNECTION_ERROR;
    }

    mbedtls_ssl_conf_read_timeout(&(tlsDataParams->conf), pNetwork->tlsConnectParams.timeout_ms);

#ifdef CONFIG_MBEDTLS_SSL_ALPN
    /* Use the AWS IoT ALPN extension for MQTT, if port 443 is requested */
    if (pNetwork->tlsConnectParams.DestinationPort == 443) {
        const char *alpnProtocols[] = { "x-amzn-mqtt-ca", NULL };
        if ((ret = mbedtls_ssl_conf_alpn_protocols(&(tlsDataParams->conf), alpnProtocols)) != 0) {
            log_error(TAG, "failed! mbedtls_ssl_conf_alpn_protocols returned -0x%x", -ret);
            _tls_destroy(pNetwork);
            return MBEDTLS_SSL_CONNECTION_ERROR;
        }
    }
#endif

    if((ret = mbedtls_ssl_setup(&(tlsDataParams->ssl), &(tlsDataParams->conf))) != 0) {
        log_error(TAG, "failed! mbedtls_ssl_setup returned -0x%x", -ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_SSL_CONNECTION_ERROR;
    }
    if((ret = mbedtls_ssl_set_hostname(&(tlsDataParams->ssl), pNetwork->tlsConnectParams.pDestinationURL)) != 0) {
        log_error(TAG, "failed! mbedtls_ssl_set_hostname returned %d", ret);
        _tls_destroy(pNetwork);
        return MBEDTLS_SSL_CONNECTION_ERROR;
    }
    mbedtls_ssl_set_bio(&(tlsDataParams->ssl), &(tlsDataParams->server_fd), mbedtls_net_send, NULL,
                        mbedtls_net_recv_timeout);
    log_trace(TAG, "ok");

    log_trace(TAG, "Performing the SSL/TLS handshake...");
    uint32_t max_timeouts = 3;
    uint32_t num_timeouts = 0;
    while((ret = mbedtls_ssl_handshake(&(tlsDataParams->ssl))) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // this is okay, try again
        } else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            num_timeouts++;
            if (num_timeouts >= max_timeouts) {
                log_error(TAG, "failed! mbedtls_ssl_handshake returned -0x%x", -ret);
                _tls_destroy(pNetwork);
                return MBEDTLS_SSL_CONNECTION_ERROR;
            }
        } else {
            log_error(TAG, "failed! mbedtls_ssl_handshake returned -0x%x", -ret);
            if(ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                log_error(TAG, "    Unable to verify the server's certificate. ");
            }
            _tls_destroy(pNetwork);
            return MBEDTLS_SSL_CONNECTION_ERROR;
        }
    }

    log_trace(TAG, "ok    [ Protocol is %s ]    [ Ciphersuite is %s ]", mbedtls_ssl_get_version(&(tlsDataParams->ssl)),
          mbedtls_ssl_get_ciphersuite(&(tlsDataParams->ssl)));
    if((ret = mbedtls_ssl_get_record_expansion(&(tlsDataParams->ssl))) >= 0) {
        log_trace(TAG, "    [ Record expansion is %d ]", ret);
    } else {
        log_trace(TAG, "    [ Record expansion is unknown (compression) ]");
    }

    log_trace(TAG, "Verifying peer X.509 certificate...");

    if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
        if((tlsDataParams->flags = mbedtls_ssl_get_verify_result(&(tlsDataParams->ssl))) != 0) {
            log_error(TAG, "failed");
            mbedtls_x509_crt_verify_info(info_buf, sizeof(info_buf), "  ! ", tlsDataParams->flags);
            log_error(TAG, "%s", info_buf);
            ret = MBEDTLS_SSL_CONNECTION_ERROR;
        } else {
            log_trace(TAG, "ok");
            ret = MBEDTLS_SUCCESS;
        }
    } else {
        log_warn(TAG, " Server Verification skipped");
        ret = MBEDTLS_SUCCESS;
    }

    if (mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)) != NULL) {
        log_trace(TAG, "Peer certificate information:");
        mbedtls_x509_crt_info((char *) info_buf, sizeof(info_buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)));
        log_trace(TAG, "%s", info_buf);
    }

    if (ret != MBEDTLS_SUCCESS) {
        _tls_destroy(pNetwork);
    }

    return (MbedtlsStatus_t) ret;
}

int32_t Mbedtls_Send( NetworkContext_t * pNetwork,
                      const void * pBuffer,
                      size_t bytesToSend ) {
    TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
    int32_t bytesSent = 0;

    bytesSent = mbedtls_ssl_write(&(tlsDataParams->ssl), pBuffer, bytesToSend);
    if (bytesSent < 0) {
        log_error(TAG, "Failed to write, ret = -0x%0X", bytesSent);
        return -MBEDTLS_SSL_WRITE_ERROR;
    }

    if (bytesSent < bytesToSend) {
        log_warn(TAG, "Partial write, attempted %u, actual %u", bytesToSend, bytesSent);
    }
    return bytesSent;
}

int32_t Mbedtls_Recv( NetworkContext_t * pNetwork,
                      void * pBuffer,
                      size_t bytesToRecv ) {
    TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
    mbedtls_ssl_context *ssl = &(tlsDataParams->ssl);

    int32_t ret = mbedtls_ssl_read(ssl, pBuffer, bytesToRecv);
    if (ret >= 0) {
        return ret;
    } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        log_warn(TAG, "ssl read WANT_READ");
        return 0;
    } else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
        // Not necessarily an error, just means we tried to read,
        // but timed out without reading anything.
        return 0;
    } else {
        log_error(TAG, "ssl read failed, ret = %d", ret);
        return -MBEDTLS_SSL_READ_ERROR;
    }
}

MbedtlsStatus_t Mbedtls_Disconnect( const NetworkContext_t * pNetwork ) {
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context*)(&(pNetwork->tlsDataParams.ssl));
    int ret = 0;
    do {
        ret = mbedtls_ssl_close_notify(ssl);
    } while(ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    /* All other negative return values indicate connection needs to be reset.
     * No further action required since this is disconnect call */
    _tls_destroy(pNetwork);
    return MBEDTLS_SUCCESS;
}

