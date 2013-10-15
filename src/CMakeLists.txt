set(PLUGIN_SRC
	main.c
)

add_library(clamav SHARED ${PLUGIN_SRC})

set_property(TARGET clamav PROPERTY VERSION ${PLUGIN_VERSION})
set_property(TARGET clamav PROPERTY SOVERSION ${PLUGIN_VERSION})
set_property(TARGET clamav PROPERTY LINK_FLAGS ${_link_flags})

target_link_libraries(clamav ${SPMFILTER_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS clamav
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/spmfilter
)
