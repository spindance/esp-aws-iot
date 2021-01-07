set(libs ${CMAKE_CURRENT_LIST_DIR}/aws-iot-device-sdk-embedded-C/libraries)
set(demos ${CMAKE_CURRENT_LIST_DIR}/aws-iot-device-sdk-embedded-C/demos)

include(${libs}/standard/coreMQTT/mqttFilePaths.cmake)
include(${libs}/standard/backoffAlgorithm/backoffAlgorithmFilePaths.cmake)
include(${libs}/aws/device-shadow-for-aws-iot-embedded-sdk/shadowFilePaths.cmake)
include(${libs}/standard/coreJSON/jsonFilePaths.cmake)
include(${demos}/logging-stack/logging.cmake)

set(COMPONENT_ADD_INCLUDEDIRS
    ${LOGGING_INCLUDE_DIRS}
    ${MQTT_INCLUDE_PUBLIC_DIRS}
    ${BACKOFF_ALGORITHM_INCLUDE_PUBLIC_DIRS}
    ${SHADOW_INCLUDE_PUBLIC_DIRS}
    ${JSON_INCLUDE_PUBLIC_DIRS}
    "port/include"
)

set(COMPONENT_SRCS
    ${MQTT_SOURCES}
    ${MQTT_SERIALIZER_SOURCES}
    ${BACKOFF_ALGORITHM_SOURCES}
    ${SHADOW_SOURCES}
    ${JSON_SOURCES}
    "port/clock.c"
    "port/network_mbedtls_wrapper.c"
)

set(COMPONENT_REQUIRES
    "mbedtls"
)

register_component()

list(APPEND EXTRA_C_FLAGS_LIST
    -Wno-type-limits
)
component_compile_options(${EXTRA_C_FLAGS_LIST})
