add_executable(session-echo-bot EXCLUDE_FROM_ALL echo-bot.cpp)
target_link_libraries(session-echo-bot PRIVATE
    libsession::client
    oxenc::oxenc
    oxen::logging)
