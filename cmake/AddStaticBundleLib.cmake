set(LIBSESSION_STATIC_BUNDLE_ROOTS "" CACHE INTERNAL "targets whose static libraries go into the static bundle lib")

# Call as:
#
#     libsession_static_bundle(target [target2 ...])
#
# to have the given target(s), and every static library they link to, combined into the static
# bundled libsession-util.a.  See libsession_static_bundle_libs() for what that means.
function(libsession_static_bundle)
    set(roots ${LIBSESSION_STATIC_BUNDLE_ROOTS})
    foreach(tgt IN LISTS ARGN)
        if(NOT "${tgt}" IN_LIST roots)
            list(APPEND roots "${tgt}")
        endif()
    endforeach()
    set(LIBSESSION_STATIC_BUNDLE_ROOTS "${roots}" CACHE INTERNAL "")
endfunction()

# Sets `out` to every static library the targets given to libsession_static_bundle() link,
# directly or through any other target, each once.  To be called once every target is complete:
# a library is named as it is created, before anything has been linked to it.
#
# Both link lists are followed, since an imported library -- every static dependency session-deps
# builds -- carries what it links to only as usage requirements.
function(libsession_static_bundle_libs out)
    set(queue ${LIBSESSION_STATIC_BUNDLE_ROOTS})
    set(seen)
    set(libs)
    while(queue)
        list(POP_FRONT queue tgt)
        # A static library's private dependencies appear in its usage requirements as LINK_ONLY.
        if(tgt MATCHES "^\\$<LINK_ONLY:(.+)>$")
            set(tgt "${CMAKE_MATCH_1}")
        endif()
        if(NOT TARGET "${tgt}")
            continue()
        endif()
        # By what it aliases, so that one library reached under two names is bundled once.
        get_target_property(aliased ${tgt} ALIASED_TARGET)
        if(aliased)
            set(tgt "${aliased}")
        endif()
        if("${tgt}" IN_LIST seen)
            continue()
        endif()
        list(APPEND seen "${tgt}")

        get_target_property(tgt_type ${tgt} TYPE)
        if(tgt_type STREQUAL STATIC_LIBRARY)
            message(STATUS "Adding ${tgt} to libsession-util bundled library list")
            list(APPEND libs "${tgt}")
        endif()

        get_target_property(tgt_imported ${tgt} IMPORTED)
        if(NOT tgt_type STREQUAL INTERFACE_LIBRARY AND NOT tgt_imported)
            get_target_property(deps ${tgt} LINK_LIBRARIES)
            if(deps)
                list(APPEND queue ${deps})
            endif()
        endif()
        get_target_property(deps ${tgt} INTERFACE_LINK_LIBRARIES)
        if(deps)
            list(APPEND queue ${deps})
        endif()
    endwhile()
    set(${out} "${libs}" PARENT_SCOPE)
endfunction()
