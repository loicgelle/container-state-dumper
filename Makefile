all:
	gcc -I. -c cgroup-tpp.c
	ar rcs cgroup-tpp.a cgroup-tpp.o
	CGO_LDFLAGS_ALLOW="cgroup-tpp.a" go build