# Double Message


## Infos
**Descrição**: Here is output of Double.sage. Catch The Flag.

**Anexos**: [double.sage](attachments/double.sage), [out.txt](attachments/out.txt)

**Solução**: [solve.sage](solve.sage)


## Análise do desafio 

Neste desafio recebemos um script ([double.sage](attachments/double.sage)) que criptografa duas mensagens ```M1```, ```M2``` utilizando RSA com o expoente público ```e = 3```. Também recebemos a saída gerada pelo script ([out.txt](attachments/out.txt)), que contém as mensagens criptografadas ```C1```, ```C2``` e o módulo ```N```.

As mensagens ```M1```, ```M2``` são geradas da seguinte forma:

<pre lang='sage'>
M1 = Flag + md5(Flag).digest()
M2 = Flag + md5(b'One more time!' + Flag).digest()
</pre>

Podemos perceber que as mensagens se diferem apenas por um texto constante de 128bits concatenado ao final da ```Flag```.


Em resumo, temos:

- ```C1```, ```C2```
- <```N```, ```e```>, onde ```N``` possui comprimento ```n = 2048``` bits e ```e``` é pequeno
- ```M1``` e ```M2``` se diferem por um *padding* de 128 bits


Como as mensagens ```M1``` e ```M2``` foram criptografadas com o mesmo módulo ```N``` e o expoente público ```e``` é pequeno, se soubermos a diferença entre ```M1```e ```M2``` conseguimos recuperar as mensagens utilizando [Franklin-Reiter related message attack](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf).

Seja ```m = floor(n / e**2)```, se a ```Flag``` possuir comprimento de até ```n - m``` bits, onde ```n``` é o comprimento do módulo ```N``` podemos recuperar a diferença entre ```M1```e ```M2``` utilizando o método de [Coppersmith](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf).



### Flag
`Defenit{Oh_C@Pp3r_SM1TH_SH0Rt_P4D_4TT4CK!!_Th1S_I5_Ve12Y_F4M0US3_D0_Y0u_UnderSt4Nd_ab@ut_LLL_AlgoriTHM?}`
