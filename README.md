# Rootkit
This is the simplest but most useful rootkit!

这个rootkit超级简单！超级有用！超级好用！

你只需要创建一个进程，然后把pid作为参数加载模块即可！别怕，模块是不会加载成功的，模块加载会失败，但事情它已经做了！

insmod ./rootkit.ko pid=1234
