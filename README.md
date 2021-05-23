# CRDIG

basic operation of DNS

## compile step
```
// start crdig
make start
// remove compiled Files
make clean
```

## dig
1. get basic DNS information 
```
./crdig www.baidu.com
```

2. like dig www.example.com +trace
```
./crdig www.baidu.com -t
```

3. use specific server for DNS
```
./crdig www.baidu.com -s8.8.8.8
```