We will by editing `myswitch_lru`

They way devopment works is we test with a bunch of test senarios.
They have some that we need to use to start. we run this with
`python ./swyard.py -t ./P1/lru_test.srpy ./P1/myswitch_lru.py --nopdb`

This is running now, but there are failling tests. 
the test file is already compiled so it is hard to figure out
all the test cases. The logic should be straight forward for 
the lru implementation.

I am unsure how too use switchyard with mininet.
We will probably have to figure it out for the spanning tree
testing.

Test cases for lru:
* What if an invalid packet is sent to our network...wrong headers etc

Test cases for STP:
* who the fuck knows Im tired.