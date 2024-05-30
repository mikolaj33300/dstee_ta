global-incdirs-y += include
srcs-y += hello_world_ta.c
cflags-hello_world_ta.c-y := -marm

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
