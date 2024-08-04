# Get Started

You can start from our sample code https://github.com/bombe-match/bombe-poc.  
Our sample code is written in `C#` with `.NET Runtime 6.0`.  

!!! warning "Don't forget the replace secret"

    Remember to replace the `secret` with your own `secret`!  
    The `secret` used in the sample and test environment is `00000000000000000000000000000000`.

```sh
git clone https://github.com/bombe-match/bombe-poc
```

## Test Environment

We have publish a playground AMI `ami-0bb2ef6ddb9e62238` for you to test your sample. In AWS console, you can launch an new EC2 and search for our AMI `ami-0bb2ef6ddb9e62238`.

![Search by AMI id](assets/ami-1.png)

Choose our AMI in Communtiy AMI.

![Choose our AMI in community AMI](assets/ami-2.png)

Inside the environment, we have already placed all 3 flags inside:

1. Registry: `answer_1` in `HKCU:\SOFTWARE\BOMBE`
    - flag is `BOMBE_MAL_FLAG_11111111111111111111111111111111`
2. Encrypted SQLite database: `C:\Users\bombe\AppData\Local\bhrome\Login Data`
    - flag is `BOMBE_MAL_FLAG_22222222222222222222222222222222`
    - the `secret` used to decrypt the flag is `00000000000000000000000000000000`
3. Memory of the specified process: `bsass.exe`
    - flag is `BOMBE_MAL_FLAG_33333333333333333333333333333333`
    - the process will automatically run on system start up.

Refers to our [Rules](../Rules) for more information.