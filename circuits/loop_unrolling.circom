pragma circom 2.0.0;



template AddPlus1 (N){
   //Declaration of signals.
   signal input in[N+1];
   signal output out1[N];
   signal output out2[N+1];
   signal output out3[N+1];
   signal output out4[N+1];
   signal output out5[N+1][N+1][N+1][N+1];
   signal output out6;

   for (var i = 0;i<N;i++) {
      out1[i] <== in[i] + i;
   }

   for (var i = 0;i<=N;i++) {
      out2[i] <== in[i] + i;
   }

   for (var i = N;i>=0;i--) {
      out3[i] <== in[i] - i;
   }

   for (var i = N;i>0;i--) {
      out4[i] <== in[i] * i;
   }

   for (var i = N+1;i<N;i++) {
      i = i + 420;
   }

   for (var i = 0;i<1;i++) {
      out6 <== in[i] + 2;
   }

   var addition = 69;
   for (var i = N;i>0;i--) {
      for (var j = 0;j<=N;j++) {
         for (var k = N;k>=0;k--) {
            for (var l = 0;l<N;l++) {
               out5[i][j][k][l] <== in[i] + addition;
               addition += l;
            }
            addition -= k;
         }
         addition *= j;
      }
      addition += i;
   }
}

component main = AddPlus1(6);
