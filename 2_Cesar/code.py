
# IMPORTANT
# IL EST PRIMORDIAL DE NE PAS CHANGER LA SIGNATURE DES FONCTIONS
# SINON LES CORRECTIONS RISQUENT DE NE PAS FONCTIONNER CORRECTEMENT
import math
import unicodedata

# used in multiplication of coincidence index
constant = 26

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
    text = remove_diacritics(text)
    out = ""
    for element in text:
        if element.isalpha():
            if element.islower():
                out += chr((ord(element) - 97 + key) % 26 + 65)
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
    text = remove_diacritics(text)
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
    text = remove_diacritics(text)
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

    return (26 - x.index(min(x))) % 26


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
    text = remove_diacritics(text)
    out = ""
    keyLength = len(key)
    index = 0
    for element in text:
        ## characters management
        if element.isalpha():
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
    text = remove_diacritics(text)
    out = ""
    keyLength = len(key)
    index = 0
    for element in text:
        ## characters management
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
    remove_diacritics(text)
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

    return IC * constant


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
    text = remove_diacritics(text)
    normalisedText = ''
    ICs = []
    maxKeyLength = 20
    line = []

    text = remove_diacritics(text)

    for element in text:
        if (122 >= ord(element) >= 97) or (90 >= ord(element) >= 65):
            normalisedText += element

    for j in range(1, maxKeyLength):

        line = []
        linesCoincidence = []

        for i in range(j):
            line.append("")

        for y in range(int(len(normalisedText) / j)):
            for x in range(j):
                line[x] += normalisedText[y * j + x]

        # add last characters
        for y in range(j):
            if(len(normalisedText) - 1 > int(len(normalisedText) / j) * j + y):
                line[y] += normalisedText[int(len(normalisedText) / j) * j + y]

        for element in line:
            linesCoincidence.append(coincidence_index(element))

        ICs.append(sum(linesCoincidence) / len(linesCoincidence))

        margin = 0.01 * constant
        if ref_ci + margin >= ICs[-1] >= ref_ci - margin:
            break

    caesarKeys = []
    for element in line:
        caesarKeys.append(chr(caesar_break(element, ref_freq) + 65))

    return caesarKeys


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
    text = remove_diacritics(text)

    output = ""
    for i in range(int(len(text) / len(vigenere_key))):

        newtext = ""
        for j in range(len(vigenere_key)):
            newtext += text[j + i * len(vigenere_key)]

        output += vigenere_encrypt(newtext, vigenere_key)
        vigenere_key = caesar_encrypt(vigenere_key, caesar_key)

    return output


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
    output = ""

    for i in range(int(len(text) / len(vigenere_key))):

        newtext = ""
        for j in range(len(vigenere_key)):
            newtext += text[j + i * len(vigenere_key)]

        output += vigenere_decrypt(newtext, vigenere_key)
        vigenere_key = caesar_encrypt(vigenere_key, caesar_key)


    return output


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
    vigenereKey = []
    caesarKey = 0

    over = False
    lengthFound = 0
    caesarFound = 0

    normalisedText = ''
    ICs = []
    maxKeyLength = 20
    lines = []

    text = remove_diacritics(text)

    for element in text:
        if (122 >= ord(element) >= 97) or (90 >= ord(element) >= 65):
            normalisedText += element

    # 1 to 20
    for j in range(1, maxKeyLength+1):

        lines = []
        linesCoincidence = []

        for i in range(j):
            lines.append("")

        for y in range(int(len(normalisedText) / j)):
            for x in range(j):
                lines[x] += normalisedText[y * j + x]

        # add last characters
        for y in range(j):
            if (len(normalisedText) - 1 > int(len(normalisedText) / j) * j + y):
                lines[y] += normalisedText[int(len(normalisedText) / j) * j + y]

        # try different keys and find the best IC
        for i in range(26):

            linesCoincidence = []
            newLines = lines.copy()
            supposedCaesarKey = i
            newElements = []

            elementIndex = 0
            for element in newLines:

                newElements.append("")

                tempIndex = 0
                for character in element:
                    newElements[elementIndex] += caesar_decrypt(character, supposedCaesarKey * tempIndex)
                    tempIndex += 1

                elementIndex += 1

            #print("1 : " + lines[0])
            #print("key :" + str(i) + " : " + newElements[0])
            # Coincidence calculation
            for element in newElements:
                linesCoincidence.append(coincidence_index(element))

            ICs.append(sum(linesCoincidence) / len(linesCoincidence))
            if ICs[-1] == max(ICs):
                print("max : " + str(max(ICs)))
                print("key : " + str(i))
                #caesarKey = i
                #lengthFound = j

            #print(max(ICs))
            print(ICs)

            #if len(ICs) > 1:
            #    print(ICs[1])
            #if len(ICs) > j*i + 1:
            #    print(ICs[1 + j*i])
            print(len(ICs))
            margin = 0.01 * constant
            # IC found
            #print(ICs)
            if ICs[-1] >= ref_ci - margin:
                print("over")
                over = True
                lengthFound = j
                caesarKey = supposedCaesarKey
                #break

        if over:
            vigUntreated = ''.join(vigenere_caesar_decrypt(text, ''.join(['A'] * lengthFound), caesarKey))
            vigenereKey = vigenere_break(vigUntreated, ref_freq, ref_ci)
            #break

    ICs.sort()
    print(ICs)
    #BestIC = min(ICs, key=lambda x: abs(x - ref_ci))
    #keyLengthNew = ICs.index(BestIC) / 26 % 20
    #caesarKeyNew = ICs.index(BestIC) % 26
    #print(ICs.index(BestIC))

    return (''.join(vigenereKey), caesarKey)


def find_vigenere_and_caesar_key(ciphertext, max_vigenere_key_length, max_caesar_key):
    best_vigenere_key = ""
    best_caesar_key = 0
    best_score = float('inf')

    for vigenere_key_length in range(1, max_vigenere_key_length + 1):
        segments = [''] * vigenere_key_length
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                segments[i % vigenere_key_length] += char

        vigenere_key = ""
        for segment in segments:
            segment_score = float('inf')
            segment_key = 0
            for shift in range(1, max_caesar_key + 1):
                decrypted_segment = caesar_decrypt(segment, shift)
                segment_coincidence = coincidence_index(decrypted_segment)
                if segment_coincidence < segment_score:
                    segment_score = segment_coincidence
                    segment_key = shift
            vigenere_key += chr(65 + (26 - segment_key) % 26)

        decrypted_text = vigenere_decrypt(ciphertext, vigenere_key)
        text_coincidence = coincidence_index(decrypted_text)

        if text_coincidence < best_score:
            best_score = text_coincidence
            best_vigenere_key = vigenere_key
            best_caesar_key = segment_key

    return best_vigenere_key, best_caesar_key

def main():

    print("Welcome to the Vigenere breaking tool\n")

    ## 2
    print("--- 2 ---")
    print(caesar_encrypt("Hello!", 3))
    print(caesar_decrypt("Khoor", 3))

    ## 2.1
    print("\n--- 2.1 ---")
    file = open("francais.txt", "r", encoding="utf-8")
    content = file.read()
    freq = freq_analysis(content)
    file.close()
    print(freq)

    newList = sorted(range(len(freq)), key=lambda k: freq[k])
    print("Ordered list :")

    # ordered list of frequency
    for i in range(26):
        print(str(chr(newList[i] + 65)) + " : " + str(freq[newList[i]]))

    ## 2.2
    print("\n--- 2.2 ---")
    print(caesar_break("Khoor", freq))

    ## 3
    print("\n--- 3 ---")
    print(vigenere_encrypt("HelloHello", "pass"))
    print(vigenere_decrypt("WEDDDHWDAO", "pass"))

    ## 3.1
    print("\n--- 3.1 ---")
    print("l'indice de coincidence mesure l'aléatoire d'un texte.")
    randomString = "wgaktpdnmezjcushzuwtkjdutvtvqstizakqdrllqccbfzegujbjgzphjfygolyzbupwecjlijoduieoteoegjnivssdodydwxzftlkpfukikjjhchddjlqgmdckzlsi"
    frenchCoincidence = coincidence_index(content)
    print(frenchCoincidence)
    print(coincidence_index(randomString))

    # 3.2
    print("\n--- 3.2 ---")
    file = open("vigenere.txt", "r", encoding="utf-8")
    vigenereContent = file.read()
    file.close()
    print("le mot cléf est : " + ''.join(vigenere_break(vigenereContent, freq, coincidence_index(content))))

    # 4
    print("\n--- 4 ---")
    print(vigenere_caesar_encrypt("testtesttesttesttest", "pass", 3))
    print(vigenere_caesar_decrypt("LHNOOKQRRNTUUQWXXTZA", "pass", 3))

    ## point 4.14, voir reponses aux questions
    file = open("vigenereAmeliore.txt", "r", encoding="utf-8")
    vigenereCaesarContent = file.read()
    file.close()

    print("\n")
    Keys = vigenere_caesar_break(vigenereCaesarContent, freq, frenchCoincidence)
    print(Keys)
    print(vigenere_caesar_decrypt(vigenereCaesarContent, Keys[0], Keys[1]))

    #print(find_vigenere_and_caesar_key(vigenereCaesarContent, 20, 25))

    #print(vigenere_caesar_decrypt(vigenereCaesarContent, "Z", 1))

    print("\nprogram end")
    print(vigenere_caesar_encrypt("testtesttesttesttest", "AAAA", 3))
    print(vigenere_caesar_decrypt("TESTWHVWZKYZCNBCFQEF", "AAAA", 3))


if __name__ == "__main__":
    main()