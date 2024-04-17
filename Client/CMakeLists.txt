# ########## Project setup ##########
PROJECT(Client)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4.5)

find_package(OpenSSL)

# ######### General setup ##########
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})

# ########## Client executable ##########
# Sources:
SET(Client_executable_SRCS
    Main.cpp
    OpenSSL_BIO_Client.cpp
)

# Headers:
SET(Client_executable_HDRS
    OpenSSL_BIO_Client.h
)



# actual target:
ADD_EXECUTABLE(Client ${Client_executable_SRCS})

target_link_libraries(Client OpenSSL::SSL OpenSSL::Crypto)

# add install target:
INSTALL(TARGETS Client DESTINATION bin)
