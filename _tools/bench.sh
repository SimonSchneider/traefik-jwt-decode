DIR=_out
mkdir -p $DIR
go test ./decoder -bench=. -benchtime 10s -benchmem -memprofile $DIR/memprofile_$1.out -cpuprofile $DIR/profile_$1.out
