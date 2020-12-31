#pragma once

#include <stdint.h>
#include <transport_interface.h>

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

// #define CONFIG_MBEDTLS_DEBUG

typedef struct {
    const char *pRootCALocation;                ///< Pointer to string containing the filename (including path) of the root CA file.
    const char *pDeviceCertLocation;            ///< Pointer to string containing the filename (including path) of the device certificate.
    const char *pDevicePrivateKeyLocation;    ///< Pointer to string containing the filename (including path) of the device private key file.
    const char *pDestinationURL;                ///< Pointer to string containing the endpoint of the MQTT service.
    uint16_t DestinationPort;            ///< Integer defining the connection port of the MQTT service.
    uint32_t timeout_ms;                ///< Unsigned integer defining the TLS handshake timeout value in milliseconds.
    bool ServerVerificationFlag;        ///< Boolean.  True = perform server certificate hostname validation.  False = skip validation \b NOT recommended.
} TLSConnectParams;

typedef struct _TLSDataParams {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    uint32_t flags;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    mbedtls_net_context server_fd;
} TLSDataParams;

struct NetworkContext {
    TLSConnectParams tlsConnectParams;
    TLSDataParams tlsDataParams;
};

typedef enum MbedtlsStatus_t {
    MBEDTLS_SUCCESS = 0,         /**< Function successfully completed. */
    MBEDTLS_INVALID_PARAMETER,   /**< At least one parameter was invalid. */
    MBEDTLS_INSUFFICIENT_MEMORY, /**< Insufficient memory required to establish connection. */
    MBEDTLS_INVALID_CREDENTIALS, /**< Provided credentials were invalid. */
    MBEDTLS_HANDSHAKE_FAILED,    /**< Performing TLS handshake with server failed. */
    MBEDTLS_API_ERROR,           /**< A call to a system API resulted in an internal error. */
    MBEDTLS_DNS_FAILURE,         /**< Resolving hostname of the server failed. */
    MBEDTLS_CONNECT_FAILURE,     /**< Initial connection to the server failed. */

    MBEDTLS_ENTROPY_SOURCE_FAILED,
    MBEDTLS_ROOT_CRT_PARSE_ERROR,
    MBEDTLS_DEVICE_CRT_PARSE_ERROR,
    MBEDTLS_PRIVATE_KEY_PARSE_ERROR,
    MBEDTLS_SOCKET_FAILED,
    MBEDTLS_UNKNOWN_HOST,
    MBEDTLS_CONNECT_FAILED,
    MBEDTLS_SSL_CONNECTION_ERROR,
    MBEDTLS_SSL_WRITE_ERROR,
    MBEDTLS_SSL_WRITE_TIMEOUT_ERROR,
    MBEDTLS_SSL_READ_ERROR,
    MBEDTLS_SSL_NOTHING_TO_READ,
    MBEDTLS_SSL_READ_TIMEOUT_ERROR,
    MBEDTLS_NULL_VALUE_ERROR,
} MbedtlsStatus_t;

MbedtlsStatus_t Mbedtls_Init(
        NetworkContext_t *pNetwork,
        const char *pRootCALocation,
        const char *pDeviceCertLocation,
        const char *pDevicePrivateKeyLocation,
        const char *pDestinationURL,
        uint16_t destinationPort,
        uint32_t timeout_ms,
        bool ServerVerificationFlag);
MbedtlsStatus_t Mbedtls_Connect( NetworkContext_t * pNetworkContext, TLSConnectParams* params);
MbedtlsStatus_t Mbedtls_Disconnect( const NetworkContext_t * pNetworkContext );

/**
 * @brief Receives data over an established TLS session.
 *
 * This can be used as #TransportInterface.recv function for receiving data
 * from the network.
 *
 * @param[in] pNetworkContext The network context created using Mbedtls_Connect API.
 * @param[out] pBuffer Buffer to receive network data into.
 * @param[in] bytesToRecv Number of bytes requested from the network.
 *
 * @return Number of bytes received if successful; negative value to indicate failure.
 * A return value of zero represents that the receive operation can be retried.
 */
int32_t Mbedtls_Recv( NetworkContext_t * pNetworkContext,
                      void * pBuffer,
                      size_t bytesToRecv );

/**
 * @brief Sends data over an established TLS session.
 *
 * This can be used as the #TransportInterface.send function to send data
 * over the network.
 *
 * @param[in] pNetworkContext The network context created using Mbedtls_Connect API.
 * @param[in] pBuffer Buffer containing the bytes to send over the network stack.
 * @param[in] bytesToSend Number of bytes to send over the network.
 *
 * @return Number of bytes sent if successful; negative value on error.
 *
 * @note This function does not return zero value because it cannot be retried
 * on send operation failure.
 */
int32_t Mbedtls_Send( NetworkContext_t * pNetworkContext,
                      const void * pBuffer,
                      size_t bytesToSend );
