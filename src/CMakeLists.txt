set(PLUGIN_SRC
	main.c
)

add_library(clamav SHARED ${PLUGIN_SRC})
target_link_libraries(clamav ${SPMFILTER_LIBRARIES})

install(TARGETS clamav
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION ${SPMFILTER_LIBRARY_DIRS}
)
