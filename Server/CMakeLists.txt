# ########## Project setup ##########
PROJECT(Server)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4.5)

find_package(OpenSSL)

# ######### General setup ##########
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})

# ########## Server executable ##########
# Sources:
SET(Server_executable_SRCS
    OpenSSL_BIO_Server.cpp
    Main.cpp
)

# Headers:
SET(Server_executable_HDRS
    OpenSSL_BIO_Server.h
)



# actual target:
ADD_EXECUTABLE(Server ${Server_executable_SRCS})

target_link_libraries(Server OpenSSL::SSL OpenSSL::Crypto)

# add install target:
INSTALL(TARGETS Server DESTINATION bin)
