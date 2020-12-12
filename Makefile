make:
	go build -o p4 main.go

clean:
	rm -fr *.o *~ p4

# run:
# 	go build -o p4 main.go
# 	./p4 input.txt
