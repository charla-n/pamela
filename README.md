# pamela
Dirty PAM Module for creating/using encrypted container with encfs

pamela.c the PAM Module<br/>
script.exp (in french, you should create your own with the "expect" tool, if your language is different) an expect script to automate encfs container creation<br/><br/>

Once the module registered, on the first login, the module will create automatically the container with the user password.<br/>
On the logout the container is unmount automatically.