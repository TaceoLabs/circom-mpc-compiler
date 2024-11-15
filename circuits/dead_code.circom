pragma circom 2.1.8;

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;

	var b_plus_one = b + 1;

   	var sum = 0;
   	for (var i = 0; i < 2; i++) {
    	sum += 1;
   	}
	
    c <== a*b_plus_one;
}

component main = Multiplier2();
