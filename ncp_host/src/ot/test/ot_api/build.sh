#!/bin/bash

BUILD_DIR="build"
SOURCE_DIR="$(pwd)"
build_options=""
echo "build directory --> $SOURCE_DIR/$BUILD_DIR"
if [ -d ${BUILD_DIR} ]; then
    echo "Clean previous work_dir"
    rm -rf ${BUILD_DIR}
    mkdir -p $BUILD_DIR
else
    mkdir -p $BUILD_DIR
    echo "Creating work_dir"
fi

cd "${BUILD_DIR}"

build()
{
    echo "building with options $build_options"
    cmake .. $build_options
    make
}

create_directory_and_build()
{
    if [ "$1" == '' ]; then
    echo "no arguments, specify the app to build"
    elif [ "$1" == 'uc1_udp_client_server' ]; then
    build_options+=' -DAPP_UC1_UDP_CLIENT_SERVER=1'
    echo "Building with option $build_options"
    elif [ "$1" == 'uc2_udp_client_server_ncp' ]; then
    build_options+=' -DAPP_UDP_CLIENT_SERVER_NCP=1'
    echo "Building with option $build_options"
	elif [ "$1" == 'uc3_ncp_ot_api_with_test' ]; then
    build_options+=' -DAPP_NCP_OT_API_AND_TEST=1'
    echo "Building with option $build_options"
    fi
    build
}

main()
{
    create_directory_and_build "$@"
}

main "$@"
