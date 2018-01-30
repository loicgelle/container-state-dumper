all:
	gcc -I. -c cgroup-tpp.c
	ar rcs cgroup-tpp.a cgroup-tpp.o
	go build