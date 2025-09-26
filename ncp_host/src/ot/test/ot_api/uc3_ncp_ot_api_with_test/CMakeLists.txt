project("uc3_ncp_ot_api_with_test")

add_executable(${PROJECT_NAME})
message(PROJECT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

set(NCP_ADAPTER_PATH
    ${PROJECT_SOURCE_DIR}/../../../../common/
)

set(NCP_HOST_PATH
    ${PROJECT_SOURCE_DIR}/../../../../
)

set(OPENTHREAD_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/../../../include
)

target_compile_definitions(${PROJECT_NAME} PUBLIC
            -DCONFIG_NCP_UART=1
            -DDEBUG_NCP_OT=1
            -DCONFIG_NCP_OT_API_TEST=1
        )


set(NCP_ADAPTER_INCLUDES
    ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_intf/uart/uart.c
    ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_intf/uart/ncp_intf_uart.c
    ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_tlv/ncp_tlv_adapter.c
    ${NCP_ADAPTER_PATH}/crc/crc.c
    ${NCP_ADAPTER_PATH}/lpm/lpm.c
)

target_include_directories(${PROJECT_NAME}
     PUBLIC
        ${NCP_ADAPTER_PATH}
        ${NCP_ADAPTER_PATH}/
        ${NCP_ADAPTER_PATH}/crc
        ${NCP_ADAPTER_PATH}/lpm
        ${NCP_ADAPTER_PATH}/ncp_adapter
        ${NCP_ADAPTER_PATH}/ncp_debug
        ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_tlv
        ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_intf
        ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_intf/uart
        ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_intf/usb
        ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_intf/spi
        ${NCP_ADAPTER_PATH}/ncp_adapter/ncp_intf/sdio
        ${OPENTHREAD_INCLUDE_PATH}
        ${NCP_HOST_PATH} # JA: dependency to wifi code from a common code
        ${NCP_HOST_PATH}/ot
 )

# target_link_libraries(${PROJECT_NAME} PRIVATE     openthread-cli-ftd
#     openthread-posix
#     openthread-ftd
#     openthread-posix
#     openthread-cli-ftd
#     openthread-hdlc
#     openthread-radio-spinel
#     openthread-spinel-rcp
#     ${OT_MBEDTLS}
#     ${READLINE_LINK_LIBRARIES}
# 	ot-posix-config
#     ot-config-ftd
#     ot-config)

target_sources(${PROJECT_NAME}
    PRIVATE
        uc3_ncp_ot_api_with_test.c
        ${NCP_HOST_PATH}/ot/ncp_ot_api.c
        ${NCP_ADAPTER_INCLUDES}
)
