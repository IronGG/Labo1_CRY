
# IMPORTANT
# IL EST PRIMORDIAL DE NE PAS CHANGER LA SIGNATURE DES FONCTIONS
# SINON LES CORRECTIONS RISQUENT DE NE PAS FONCTIONNER CORRECTEMENT
import math
import unicodedata

def remove_diacritics(text):
    normalized_text = unicodedata.normalize('NFD', text)
    stripped_text = ''.join(c for c in normalized_text if not unicodedata.combining(c))
    return stripped_text


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
            # TODO : Key capslock ?
            if element.islower():
                # 97 + 97 = 194
                if(key[index].islower()):
                    out += chr(((ord(element) - 194 + ord(key[index])) % 26) + 65)
                else:
                    out += chr(((ord(element) - 162 + ord(key[index])) % 26) + 65)

            else:
                # 65 + 65 = 194
                if(key[index].islower()):
                    out += chr(((ord(element) - 162 + ord(key[index])) % 26) + 65)
                else:
                    out += chr(((ord(element) - 130 + ord(key[index])) % 26) + 65)

            index += 1
            index = index % keyLength

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
            if element.islower():
                if(key[index].islower()):
                    out += chr(((ord(element) - ord(key[index])) % 26) + 65)
                else:
                    out += chr(((ord(element) - 32 - ord(key[index])) % 26) + 65)

            else:
                if(key[index].islower()):
                    out += chr(((ord(element) + 32 - ord(key[index])) % 26) + 65)
                else:
                    out += chr(((ord(element) - ord(key[index])) % 26) + 65)

            index += 1
            index = index % keyLength

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
    lettersTotal = [0] * 26
    IC = 0
    count = 0

    for element in text:
        if (122 >= ord(element) >= 97) or (90 >= ord(element) >= 65):
            count += 1
            if element.islower():
                letters[ord(element) - 97] += 1
            else:
                letters[ord(element) - 65] += 1

    for i in range(26):
        lettersTotal[i] = letters[i] * (letters[i] - 1)
        IC += lettersTotal[i]

    if ((count * (count - 1)) != 0):
        IC = IC / (count * (count - 1))
    else:
        return 0

    return IC


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
    normalisedText = ''
    ICs = []
    maxKeyLength = 40
    line = []

    text = remove_diacritics(text)

    for element in text:
        if (122 >= ord(element) >= 97) or (90 >= ord(element) >= 65):
            normalisedText += element

    for j in range(4, maxKeyLength):

        line = []
        linesCoincidence = []

        for i in range(j):
            line.append("")

        #print("range")
        #print(int(len(normalisedText) / j))

        for y in range(int(len(normalisedText) / j)):
            for x in range(j):
                line[x] += normalisedText[y * j + x]

        #print("test")
        #print(line[0])

        for element in line:
            linesCoincidence.append(coincidence_index(element))

        #print(linesCoincidence)
        ICs.append(sum(linesCoincidence) / len(linesCoincidence))

        margin = 0.01
        if ref_ci + margin >= ICs[-1] >= ref_ci - margin:
            print("insideIf")
            print(ICs[-1])
            break

        #if(j == 33):
        #    print(linesCoincidence)
        #    print(sum(linesCoincidence) / len(linesCoincidence))
        #    print(ICs)

        #splitted = [normalisedText[i:i+j] for i in range(0, len(normalisedText), j)]
        #print("HERE _")
        #print(splitted)
        #ICs.append([])
        #for element in splitted:
        #     print(element)
        #    ICs[j-4].append(coincidence_index(element))

    #for i in range(4, maxKeyLength):
    #    currentVal = sum(ICs[i-4]) / len(ICs[i-4])
    #    print(str(i) + " : " + str(currentVal))

    print("there")
    #print(ICs)
    counter = 4
    for element in ICs:
        print(str(counter) + " : " + str(element))
        counter += 1

    newLines = []
    for element in line:
        newLines.append(caesar_break(element, ref_freq))

    output = ""

    index = 0
    for characters in newLines[0]:
        for element in newLines:
            output += element[index]
        index += 1



    print("max : " + str(ICs.index(max(ICs)) + 4) + " : " + str(max(ICs)))

    # Que faire pour le reste qui n'est pas parfaitement divisible ?

    return output


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
    print(vigenere_decrypt("WEDDD", "pass"))

    # print(coincidence_index(content))
    # print(coincidence_index('''abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'''))

    # Plus c'est petit, plus c'est aléatoire
    # https://www.random.org/strings/
    # avec un texte parfaitement aléatoire nos devrions être à 1

    # donc lettre + lettre va nous donner une valeur non aléatoire si les 2 sont composés de vrais mots


    # Program to read the entire file using read() function
    file = open("francais.txt", "r", encoding="utf-8")
    frenchContent = file.read()
    frenchFreq = freq_analysis(content)
    file.close()

    # ceciestunephraselonguetreslongue
    myKey = "ceciestunephrase1  1§"

    print(len(myKey))

    vigenereContent = vigenere_encrypt(frenchContent, myKey)

    # print(content)

    # print(coincidence_index(content))

    print(coincidence_index(remove_diacritics(frenchContent)))
    # print(coincidence_index("ceciestunephraselonguetreslongue"))

    print(vigenere_break(vigenereContent, frenchFreq, coincidence_index(remove_diacritics(frenchContent))))


    print("Text from cyberlearn :")

    # Program to read the entire file using read() function
    file = open("vigenere.txt", "r", encoding="utf-8")
    content = file.read()
    freq = freq_analysis(content)
    file.close()

    print(vigenere_break(content, frenchFreq, coincidence_index(remove_diacritics(frenchContent))))


if __name__ == "__main__":
    main()