pragma circom 2.0.0;



template AddPlus1 (N){
   //Declaration of signals.
   signal input in[N];
   signal output out[N];

   for (var i = 0;i<N;i++) {
      out[i] <== in[i] + i;
   }
}

component main = AddPlus1(4);
