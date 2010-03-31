set(MAN_SRC
	spmfilter-clamav.1)

foreach(man ${MAN_SRC})
	create_manpage(${man})
endforeach(man)

