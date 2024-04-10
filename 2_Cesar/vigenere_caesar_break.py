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

    normalisedText = ''
    ICs = []
    maxKeyLength = 20
    lines = []

    text = remove_diacritics(text)

    for element in text:
        if (122 >= ord(element) >= 97) or (90 >= ord(element) >= 65):
            normalisedText += element

    for j in range(1, maxKeyLength):

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

        for element in lines:

            # check longueur du décalage jusqu'à boucle (ou jusqu'à la fin si pas de boucle)
            caesarVigKey = vigenere_break(element, ref_freq, ref_ci)
            caesarKey = (ord(caesarVigKey[0]) - ord(caesarVigKey[1])) % 26 # recup de la clé de caesar

            # charactères sans cesar
            index = 0
            #print(element)
            for character in element:
                character = caesar_decrypt(character, caesarKey * index)
                index += 1

        # text en vigenere à maintenant déchiffrer
        for element in lines:
            linesCoincidence.append(coincidence_index(element))

        ICs.append(sum(linesCoincidence) / len(linesCoincidence))

        margin = 0.01 * constant
        if ref_ci + margin >= ICs[-1] >= ref_ci - margin:
            break

    for element in lines:
        vigenereKey.append(chr(caesar_break(element, ref_freq) + 65))


    return (''.join(vigenereKey), caesarKey)