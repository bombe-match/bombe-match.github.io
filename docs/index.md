# Get Started

Follow the steps below to get started:

1. [Write your code](#write-your-code)
2. [Test your code](#test-your-code)
3. [Submit the binary](#submit-the-binary)
4. [Register match](#register-match)

## Write your code

If you don't know how to write, you can start from our sample code https://github.com/bombe-match/bombe-poc. Our sample code is written in `C#` with `.NET Runtime 6.0`. You can use Visual Studio to compile the binary.

!!! warning "Don't forget to replace the secret"

    Remember to replace the `secret` with your own `secret`!  
    Every user will have a unique `secret`, you need to send it with your answer.  
    The `secret` used in the sample and test environment is `00000000000000000000000000000000`.

```sh
git clone https://github.com/bombe-match/bombe-poc
```

## Test your code

We have published a playground AMI `ami-0fdcac36b3de4482e` (us-west-2) for you to test your sample. In the AWS console, you can launch a new EC2 instance and search for our AMI `ami-0fdcac36b3de4482e`.

!!! warning "Remember to switch region"

    You need to switch your region to `us-west-2` in order to use our AMI.

![Search by AMI id](/assets/ami-1.png)

Choose our AMI in Community AMIs.

![Choose our AMI in community AMI](/assets/ami-2.png)

!!! info "Login via RDP"

    To use RDP with your EC2 instance, first expose the EC2 instance to the internet. 
    Then, connect to the EC2 instance using its public IP via RDP. 
    The default Administrator password is `Bombe@2024`. Be sure to change this password after logging in.

Inside the environment, we have already placed three flags:

1. Registry: `answer_1` in `HKLM:\SOFTWARE\BOMBE`
    - flag is `BOMBE_MAL_FLAG_11111111111111111111111111111111`
2. Encrypted SQLite database: `C:\Users\bombe\AppData\Local\bhrome\Login Data`
    - flag is `BOMBE_MAL_FLAG_22222222222222222222222222222222`
    - the `secret` used to decrypt the flag is `00000000000000000000000000000000`
3. Memory of the specified process: `bsass.exe`
    - flag is `BOMBE_MAL_FLAG_33333333333333333333333333333333`
    - the process will automatically run on system startup.

## Submit the binary

After preparing your binary, you can upload it to our contest website. Each upload will be assigned a version number, with a new version created every time you submit. Only the latest version of your binary will be used in the competition.

![](/assets/submit.png)

## Congrats

Now you know how our game works.  
You can refer to our [Rules](/Rules) for more information.
