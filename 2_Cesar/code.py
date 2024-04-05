
# IMPORTANT
# IL EST PRIMORDIAL DE NE PAS CHANGER LA SIGNATURE DES FONCTIONS
# SINON LES CORRECTIONS RISQUENT DE NE PAS FONCTIONNER CORRECTEMENT
import math


def caesar_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the shift which is a number

    Returns
    -------
    the ciphertext of <text> encrypted with Caesar under key <key>
    """
    # TODO
    out = ""
    for element in text:
        if element.isalpha():
            if element.islower():
                out += chr((ord(element) - 97 + key) % 26 + 65  )
            else:
                out += chr((ord(element) - 65 + key) % 26 + 65)

    return out


def caesar_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the shift which is a number

    Returns
    -------
    the plaintext of <text> decrypted with Caesar under key <key>
    """
    # TODO
    out = ""
    for element in text:
        if element.isalpha():
            if element.islower():
                out += chr((ord(element) - 97 - key) % 26 + 97)
            else:
                out += chr((ord(element) - 65 - key) % 26 + 65)

    return out


def freq_analysis(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    list
        the frequencies of every letter (a-z) in the text.

    """
    # Each value in the vector should be in the range [0, 1]
    freq_vector = [0] * 26
    # TODO
    for element in text:
        if (122 >= ord(element) >= 97) or (90 >= ord(element) >= 65):
            if element.islower():
                freq_vector[ord(element) - 97] += 1
            else:
                freq_vector[ord(element) - 65] += 1

    return freq_vector




def caesar_break(text, ref_freq):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text

    Returns
    -------
    a number corresponding to the caesar key
    """
    # TODO
    currentFreq = freq_analysis(text)
    x = [0] * 26

    test = currentFreq[1]
    totalCurrent = 0
    totalOld = 0

    expected = [0] * 26

    for i in range(26):
        totalCurrent += currentFreq[i]
        totalOld += ref_freq[i]

    for i in range(26):
        ref_freq[i] = ref_freq[i] / totalOld
        expected[i] = ref_freq[i] * totalCurrent

    # nous cherchons à minimser x
    for i in range(26):
        for j in range(26):
            x[i] += (currentFreq[j-i] - expected[j])**2 / expected[j]

    print("le décalage est de : " + str(x.index(min(x))))

    return caesar_encrypt(text, x.index(min(x)))


def vigenere_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the ciphertext of <text> encrypted with Vigenere under key <key>
    """
    out = ""
    keyLength = len(key)
    index = 0
    # print(chr(ord(key[1])) % 26)
    for element in text:
        if element.isalpha():
            index += 1
            index = index % keyLength
            if element.islower():
                out += chr((ord(element) - 97 + ord(key[index]) % 26) % 26 + 65)
            else:
                out += chr((ord(element) - 65 + ord(key[index]) % 26) % 26 + 65)

    return out


def vigenere_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the plaintext of <text> decrypted with Vigenere under key <key>
    """
    out = ""
    keyLength = len(key)
    index = 0
    for element in text:
        if element.isalpha():
            index += 1
            index = index % keyLength
            if element.islower():
                out += chr((ord(element) - 97 - ord(key[index]) % 26) % 26 + 97)
            else:
                out += chr((ord(element) - 65 - ord(key[index]) % 26) % 26 + 65)

    return out


def coincidence_index(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    the index of coincidence of the text
    """
    # TODO
    letters = [0] * 26
    IC = [0] * 26
    SumLetters = 0
    count = len(text)

    for element in text:
        if (122 >= ord(element) >= 97) or (90 >= ord(element) >= 65):
            if element.islower():
                letters[ord(element) - 97] += 1
            else:
                letters[ord(element) - 65] += 1

    for i in range(26):
        IC[i] = letters[i] * (letters[i] - 1)
        SumLetters += IC[i]

    SumLetters = 26 * SumLetters / (count * (count - 1))

    print(1-SumLetters)

    return SumLetters


def vigenere_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    # TODO
    return ''


def vigenere_caesar_encrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the ciphertext of <text> encrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    # TODO
    return ""


def vigenere_caesar_decrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to decrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the plaintext of <text> decrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    # TODO
    return ""


def vigenere_caesar_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    pair
        the keyword corresponding to the vigenere key used to obtain the ciphertext
        the number corresponding to the caesar key used to obtain the ciphertext
    """
    # TODO you can delete the next lines if needed
    vigenere_key = ""
    caesar_key = ''
    return (vigenere_key, caesar_key)


def main():
    print("Welcome to the Vigenere breaking tool")
    # TODO something
    print(caesar_encrypt("Hello!", 3))
    print(caesar_decrypt("Khoor", 3))

    # Program to read the entire file using read() function
    file = open("Red_Mesa.txt", "r", encoding="utf-8")
    content = file.read()
    freq = freq_analysis(content)
    file.close()

    newList = sorted(range(len(freq)), key=lambda k: freq[k])
    print("Ordered list :")

    # ordered list of frequency
    for i in range(26):
        print(str(chr(newList[i] + 65)) + " : " + str(freq[newList[i]]))

    print("program end")

    # Program to read the entire file using read() function
    file = open("The_Battle_Of_Life.txt", "r", encoding="utf-8")
    content = file.read()
    secondBook = freq_analysis(content)
    file.close()

    print(caesar_break(caesar_encrypt(content, 6), freq))

    print(vigenere_encrypt("Hello", "pass"))
    print(vigenere_decrypt("APWTH", "pass"))

    print(coincidence_index(content))
    print(coincidence_index('''abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'''))

    # Plus c'est petit, plus c'est aléatoire
    # https://www.random.org/strings/
    # avec un texte parfaitement aléatoire nos devrions être à 1

    # donc lettre + lettre va nous donner une valeur non aléatoire si les 2 sont composés de vrais mots



if __name__ == "__main__":
    main()