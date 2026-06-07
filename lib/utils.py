import random
import string


def random_password(length=16):
    """Return a random alphanumeric password of the given length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))


def random_sentence(length=5):
    """Return *length* space-separated words sampled from a Lorem-ipsum word list."""
    words = ["sed", "ut", "perspiciatis", "unde", "omnis", "iste", "natus", "error", "sit", "voluptatem", "accusantium",
             "doloremque", "laudantium,", "totam", "rem", "aperiam,", "eaque", "ipsa", "quae", "ab", "illo",
             "inventore", "veritatis", "et", "quasi", "architecto", "beatae", "vitae", "dicta", "sunt", "explicabo",
             "nemo", "enim", "ipsam", "voluptatem", "quia", "voluptas", "sit", "aspernatur", "aut", "odit", "aut",
             "fugit,", "sed", "quia", "consequuntur", "magni", "dolores", "eos", "qui", "ratione", "voluptatem",
             "sequi", "nesciunt", "neque", "porro", "quisquam", "est,", "qui", "dolorem", "ipsum", "quia", "dolor",
             "sit", "amet,", "consectetur,", "adipisci", "velit,", "sed", "quia", "non", "numquam", "eius", "modi",
             "tempora", "incidunt", "ut", "labore", "et", "dolore", "magnam", "aliquam", "quaerat", "voluptatem", "ut",
             "enim", "ad", "minima", "veniam,", "quis", "nostrum", "exercitationem", "ullam", "corporis", "suscipit",
             "laboriosam,", "nisi", "ut", "aliquid", "ex", "ea", "commodi", "consequatur", "quis", "autem", "vel",
             "eum", "iure", "reprehenderit", "qui", "in", "ea", "voluptate", "velit", "esse", "quam", "nihil",
             "molestiae", "consequatur,", "vel", "illum", "qui", "dolorem", "eum", "fugiat", "quo", "voluptas", "nulla",
             "pariatur"]
    return " ".join(random.sample(words, length))
