#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pakeMail con varios participantes - Orientado a Objetos
utilizando (Password) Authenticated Key Establishment: from 2-party to group (y PakeMail y SPAKE2)
"""

import time
from pakemod import PakeClient
from spake2.parameters.i1024 import Params1024
import base64
from spake2 import util
from random import randint
from hashlib import sha256


def run_local_pake_test():
    """
    Función de PakeMail 
    https://github.com/CryptographySandbox/PakeMail/blob/main/src/PakeMail_sandbox.py
    -
    Se ha modificado la función para que devuelva la clave final obtenida por los participantes.
    -
    Devuelve:
        key -> clave establecida por los particpantes mediante el protocolo PAKE
    """
    # executionTime = float(0)
    # start = time.process_time()

    pakeClientA = PakeClient("A", "pass", "test+senderA@gmail.com", parameters=Params1024)
    pakeClientB = PakeClient("B", "pass", "test+receiverB@gmail.com", parameters=Params1024)

    pakeClientA.registerRemotePakeClient(pakeClientB)
    pakeClientB.registerRemotePakeClient(pakeClientA)

    pakeClientA.setup(localTest=True)
    pakeClientB.setup(localTest=True)

    pakeMsgA1 = pakeClientA.pakeMessage
    pakeMsgB2 = pakeClientB.pakeMessage

    pakeClientA.computeKey(pakeMsgB2)
    keyA = pakeClientA.key

    pakeClientB.computeKey(pakeMsgA1)
    keyB = pakeClientB.key

    print(base64.b64encode(keyA))
    print(base64.b64encode(keyB))
    print("Intermediate secret keys match: ", keyA == keyB)

    print("Key confirmation starts...")

    kA, aMacKeyA, aMacKeyB = pakeClientA.runKeyDerivation()
    pakeClientA.computeTranscript()
    macMessageA = pakeClientA.pkAfpr + pakeClientA.pkBfpr + pakeClientA.transcript
    print("MAC message A:", macMessageA)
    tauA = pakeClientA.computeMAC(aMacKeyA, macMessageA)
    pakeClientA.createMacMsg(tauA, writeToFile=True)
    print("tau_A :\n", tauA)

    expected_tauB = pakeClientA.computeMAC(aMacKeyB, macMessageA)
    print("expected tau_B :\n", expected_tauB)

    kB, bMacKeyA, bMacKeyB = pakeClientB.runKeyDerivation()
    pakeClientB.computeTranscript()
    macMessageB = pakeClientB.pkAfpr + pakeClientB.pkBfpr + pakeClientB.transcript
    print("MAC message B:", macMessageB)
    tauB = pakeClientB.computeMAC(bMacKeyB, macMessageB)
    pakeClientB.createMacMsg(tauB, writeToFile=True)
    print("tau_B :\n", tauB)

    expected_tauA = pakeClientB.computeMAC(bMacKeyA, macMessageB)
    print("expected tau_A :\n", expected_tauA)

    print("----------------------------------------------------")
    print("Tags match on A side: ", tauB == expected_tauB)
    print("Tags match on B side: ", tauA == expected_tauA)
    print("Final secret keys are: \n{0}\n{1}\nand have length {2} and {3}".format(base64.b64encode(kA),
                                                                                  base64.b64encode(kB), len(kA),
                                                                                  len(kB)))
    print("Final secret keys match: ", kA == kB)
    key = kA

    # executionTime = (time.process_time() - start)
    # print("Local PakeMail execution time: ", executionTime)


    return key


def commitment(key, value):
    """
    Modificación de https://github.com/raphaelrrcoelho/commitment-scheme/blob/master/commitment.py
    para que la clave sea introducida como parámetro.
    -
    Parámetros:
        key -> clave para realizar el commitment
        value -> valor sobre el que se realiza el commitment (valor con el que se compromete el usuario)
    -
    Devuelve:
        commit
    """
    key = str(key)
    value = str(value)
    com = hashing(key + value)
    return com


def verify(com_key_val):
    """
    https://github.com/raphaelrrcoelho/commitment-scheme/blob/master/commitment.py
    Verificación de commitment
    -
    Parámetros:
        com_key_val -> lista que contiene los tres valores siguientes:
        com -> valor del commitment que se quiere comprobar
        key -> clave con la que se realizó el commitment
        value -> valor al que se había comprometido el usuario
    -
    Devuelve:
        True si el commitment es correcto
        False si no es correcto
    """
    if (len(com_key_val) != 3):
        print("\nERROR")
        #exit()
    com = com_key_val[0]
    key = com_key_val[1]
    value = com_key_val[2]
    key = str(key)
    value = str(value)
    return (com == hashing(key + value))


def hashing(value):
    """
    https://github.com/raphaelrrcoelho/commitment-scheme/blob/master/commitment.py
    -
    Realiza hash sha256
    -
    Parámetros:
        value -> valor sobre el que se realiza el hash
    -
    Devuelve
        El hash de value
    """
    encoded_value = value.encode()
    return sha256(encoded_value).hexdigest()



def compute_k(key, xorKeysAllUsers, userId, j):
    """
    Esta función se utiliza en el cálculo de la clave de sesión
    -
    Parámetros:
        key (int) -> clave Ki del usuario 
        xorKeys (list[int]) -> claves Xi de todos los usuarios
        userId (int) -> id del usuario (en {0,1,...,numParticipantes)
        j (int) -> contador, índice del valor Kj a calcular
    -
    Devuelve:
        result -> clave Kj que pertenecerá a la master key K
    """
    result = key
    numParticipantes = len(xorKeysAllUsers)
    numSumas = (userId - j) % numParticipantes
    for i in range(numSumas):
        result = result ^ xorKeysAllUsers[(userId-i-1)%numParticipantes]
    return result

    

####################################################################

class User:
    """
    La clase User representa a cada usuario o participante del protocolo
    """

    def __init__(self, id):
        """
        Inicialización del objeto User
        -
        Parámetros:
            id (int): identificador del usuario.
        """
        self.id = id
        self.userIds = None

        self.pakeKeyLeft = None
        self.pakeKeyRight = None

        self.passwordLeft = None
        self.passwordRight = None

        self.xorKeys = None

        self.commitmentValue = None
        self.commitmentKey = None

        self.commitmentsAllUsers = None
        self.xorKeysAllUsers = None

        self.verifyXorKeys = None
        self.verifyCommitments = None

        self.masterKey = []
        self.sessionKey = None
        self.sessionId = None

        self.acc = False



    def set_pake_2party(self, pakeKeyLeft, pakeKeyRight):
        """
        Establece los valores de las claves establecidas con el usuario a su izquierda y a su derecha mediante PAKE
        -
        Parámetros:
            pakeKeyLeft (): clave que el usuario i establece con el usuario i-1
            pakeKeyRight (): clave que el usuario i establece con el usuario i+1
        """
        self.pakeKeyLeft = util.bytes_to_number(pakeKeyLeft)
        self.pakeKeyRight = util.bytes_to_number(pakeKeyRight)


    def compute_pake_key():
        run_local_pake_test()


    def compute_xorKeys(self):
        """
        Calcula la operación XOR entre las claves pakeKeyLeft y pakeKeyRight
        y establece este valor en el atributo xorKeys
        -
        pakeKeyLeft (int)
        pakeKeyRight (int)
        """
        self.xorKeys = self.pakeKeyLeft ^ self.pakeKeyRight


    def compute_commitment(self):
        """
        El usuario se compromete con un valor commitmentValue aleatorio y como clave
        se utiliza el valor establecido en xorKeys
        -
        commitmentValue (int)
        xorKeys (int)
        """
        self.commitmentValue = randint(1, 100000000)
        self.commitmentKey = self.xorKeys
        self.commitment = commitment(self.commitmentKey, self.commitmentValue)

    def check_xorKeys(self, keys):
        """
        Comprueba que la operación XOR de las claves xorKey de todos los participantes es igual a 0
        -
        Parámetros:
            keys (list[int]): lista de las claves de todos los usuarios
        """
        result = 0
        for k in keys:
            result = result ^ k
        self.verifyXorKeys = result
        if (result != 0):
            self.acc = False
            print("\ERROR EN LA COMPROBACIÓN DE xorKeys")

    def verify_commitments(self, commitmentKeysAndValues):
        """
        Comprueba que los valores de los commitments del resto de usuarios son correctos
        -
        Parámetros:
            commitmentsKeysAndValues (list[commitment,key,value])
        """
        auxVerify = True
        for i in commitmentKeysAndValues:
            if (verify(i) != True):
                auxVerify = False
                self.acc = False
                print("\ERROR EN LA COMPROBACIÓN DE commitment")
        self.verifyCommitments = auxVerify


    def compute_master_key(self):
        """
        Calcula la clave maestra
        """
        for j in range(len(self.userIds)):
            if (j == self.id):
                self.masterKey.append(self.pakeKeyLeft)
            else:
                self.masterKey.append(compute_k(self.pakeKeyLeft, self.xorKeysAllUsers, self.id, j))
        for id in self.userIds:
            self.masterKey.append(id)
        


    def compute_session_key(self):
        """
        Calcula la clave de sesión, concatenando los elementos de la clave maestra, añadiendo un 0 al final
        y aplicando la función hash SHA256
        """
        value = ""
        for k in self.masterKey:
            value = value + str(k)
        value = value + '0'
        encoded_value = value.encode()
        self.sessionKey = sha256(encoded_value).hexdigest()


    def compute_session_id(self):
        """
        Calcula la clave de sesión, concatenando los elementos de la clave maestra, añadiendo un 1 al final
        y aplicando la función hash SHA256
        """
        value = ""
        for k in self.masterKey:
            value = value + str(k)
        value = value + '1'
        encoded_value = value.encode()
        self.sessionId = sha256(encoded_value).hexdigest() 




class Session:
    """
    La clase Session representa una ejecución del protocolo en la que varios usuarios quieren establecer una clave común
    Este objeto simplemente se utiliza para representar la clave final de la sesión que establecen los usuarios,
    pero cada uno realizará las operaciones en local, no las realiza una entidad sesión; y para representar
    los valores que son conocidos por todos los usuarios (cuando se realiza un broadcast)
    """

    def __init__(self, userIds):
        """
        Inicialización del objeto Session
        -
        Parámetros:
            userIds (list[int]): lista de los identificadores de los usuarios que participan en la sesión
        """
        self.userIds = userIds
        self.commitments = None
        self.commitmentsVerificationValues = []
        self.xorKeys = []
        self.masterKeys = []
        self.sessionKey = None
        self.sessionId = None



    def set_commitments(self, commitments):
        """
        Los valores con los que se compromenten los usuarios son compartidos para todos los participantes de la sesión
        y se guardan en el objeto Session.
        Cada commitment estará asociado al id del usuario correspondiente
        -
        Parámetros:
            commitments[id,commitment] (list[int,int])
        """
        self.commitments = commitments
        



###################################################

def ejemplo_3_usuarios():

    tiempoEjecucion = float(0)
    tInicio = time.process_time()

    # se crean los 3 participantes/usuarios: 0,1,2
    user1 = User(0)
    user2 = User(1)
    user3 = User(2)

    # se crea la sesión en la que participan los usuarios anteriores
    session1 = Session([user1.id, user2.id, user3.id])

    # se indica con qué usuarios va a establecer la sesión
    user1.userIds = session1.userIds
    user2.userIds = session1.userIds
    user3.userIds = session1.userIds


    # ROUND 0
    # intercambio de claves PAKE entre cada dos participantes
    keysPake = []
    for i in range(len(session1.userIds)):
        keysPake.append(run_local_pake_test())

    user1.set_pake_2party(keysPake[0], keysPake[1])
    user2.set_pake_2party(keysPake[1], keysPake[2])
    user3.set_pake_2party(keysPake[2], keysPake[0])

    tiempoDesdeRound1 = float(0)
    tInicioRound1 = time.process_time()

    # ROUND 1
    # Computation: xorKeys
    user1.compute_xorKeys()
    user2.compute_xorKeys()
    user3.compute_xorKeys()

    # Computation: commitments
    user1.compute_commitment()
    user2.compute_commitment()
    user3.compute_commitment()

    # Broadcast: commitments
    session1.set_commitments([[user1.id, user1.commitment], [user2.id, user2.commitment], [user3.id, user3.commitment]])


    # ROUND 2
    # Broadcast: se establece commitmentVerificationValues en el objeto Session
    # Estos valores servirán para comprobar la validez de los commitments
    session1.xorKeys = [[user1.id, user1.xorKeys], [user2.id, user2.xorKeys], [user3.id, user3.xorKeys]]
    user1.xorKeysAllUsers = [user1.xorKeys, user2.xorKeys, user3.xorKeys]
    user2.xorKeysAllUsers = [user1.xorKeys, user2.xorKeys, user3.xorKeys]
    user3.xorKeysAllUsers = [user1.xorKeys, user2.xorKeys, user3.xorKeys]
    session1.commitmentVerificationValues = [[user1.id, user1.commitmentValue], [user2.id, user2.commitmentValue],
                                             [user3.id, user3.commitmentValue]]

    # Check: xorKeys
    user1.check_xorKeys([user1.xorKeys, user2.xorKeys, user3.xorKeys])
    user2.check_xorKeys([user1.xorKeys, user2.xorKeys, user3.xorKeys])
    user2.check_xorKeys([user1.xorKeys, user2.xorKeys, user3.xorKeys])

    # Check: verify commitments
    commitmentKeysAndValues = []
    commitmentKeysAndValues.append([user1.commitment, user1.commitmentKey, user1.commitmentValue])
    commitmentKeysAndValues.append([user2.commitment, user2.commitmentKey, user2.commitmentValue])
    commitmentKeysAndValues.append([user3.commitment, user3.commitmentKey, user3.commitmentValue])
    user1.verify_commitments(commitmentKeysAndValues)
    user2.verify_commitments(commitmentKeysAndValues)
    user3.verify_commitments(commitmentKeysAndValues)

    # Computation: masterKey
    user1.compute_master_key()
    user2.compute_master_key()
    user3.compute_master_key()

    print("\nMASTER KEYS")
    print("user1")
    print(user1.masterKey)
    print("user2")
    print(user2.masterKey)
    print("user3")
    print(user3.masterKey)
    #print("\nMASTER KEYS")
    #print(session.masterKeys)
    if ((user1.masterKey == user2.masterKey) and (user2.masterKey == user3.masterKey)):
        session1.masterKeys = user1.masterKey

    # Computation: sessionKey
    user1.compute_session_key()
    user2.compute_session_key()
    user3.compute_session_key()

    print("\nSESSION KEYS")
    print(user1.sessionKey)
    print(user2.sessionKey)
    print(user3.sessionKey)

    # Computation: sessionId
    user1.compute_session_id()
    user2.compute_session_id()
    user3.compute_session_id()

    print("\nSESSION IDs")
    print(user1.sessionId)
    print(user2.sessionId)
    print(user3.sessionId)

    # la clave es aceptada y finaliza el protocolo
    user1.acc = True
    user2.acc = True
    user3.acc = True

    tiempoEjecucion = (time.process_time() - tInicio)
    print("\nTiempo de ejecución: ", tiempoEjecucion)

    tiempoEjecucionRound1 = (time.process_time() - tInicioRound1)
    print("\nTiempo de ejecución desde la ronda 1 (excluyendo intercambio de claves PAKE): ", tiempoEjecucionRound1)
    



def ejemplo_n_usuarios(numParticipantes):

    tiempoEjecucion = float(0)
    tInicio = time.process_time()

    # crear usuarios y establecer sus ids
    usuarios = [] #array de objetos User
    for i in range(numParticipantes):
        usuarios.append(User(i))
    
    # crear la sesión
    userIds = []
    for u in usuarios:
        userIds.append(u.id)
    session = Session(userIds)

    # establecer los ids de los usuarios con los que se establece la sesión
    for u in usuarios:
        u.userIds = session.userIds

    # ROUND 0
    # intercambio de claves PAKE entre cada dos participantes
    keysPake = []
    for i in range(len(session.userIds)):
        keysPake.append(run_local_pake_test())

    for u in usuarios:
        u.set_pake_2party(keysPake[u.id], keysPake[(u.id+1)%numParticipantes])

    tiempoDesdeRound1 = float(0)
    tInicioRound1 = time.process_time()

    # ROUND 1
    # Computation: xorKeys
    for u in usuarios:
        u.compute_xorKeys()

    # Computation: commitments
    for u in usuarios:
        u.compute_commitment()

    # ROUND 2
    # Broadcast: se establece commitmentVerificationValues en el objeto Session
    # Estos valores servirán para comprobar la validez de los commitments
    for u in usuarios:
        session.xorKeys.append(u.xorKeys)
        session.commitmentsVerificationValues.append(u.commitmentValue)

    for u in usuarios:
        u.xorKeysAllUsers = session.xorKeys
        
    # Check: xorKeys
    for u in usuarios:
        u.check_xorKeys(u.xorKeysAllUsers)

    # Check: verify commitments
    commitmentKeysAndValues = []
    for u in usuarios:
        commitmentKeysAndValues.append([u.commitment, u.commitmentKey, u.commitmentValue])
    
    for u in usuarios:
        u.verify_commitments(commitmentKeysAndValues)

    # Computation: masterKey
    print("\nMaster Keys")
    for u in usuarios:
        u.compute_master_key()
        print(u.masterKey)
        session.masterKeys = u.masterKey

    # Computation: sessionKey
    print("\nSession key")

    for u in usuarios:
        u.compute_session_key()
        print(u.sessionKey)

    # Computation: sessionId
    print("\nSession id")
    for u in usuarios:
        u.compute_session_id()
        print(u.sessionId)

    for u in usuarios:
        u.acc = True

    tiempoEjecucion = (time.process_time() - tInicio)
    print("\nTiempo de ejecución: ", tiempoEjecucion)

    tiempoEjecucionRound1 = (time.process_time() - tInicioRound1)
    print("\nTiempo de ejecución desde la ronda 1 (excluyendo intercambio de claves PAKE): ", tiempoEjecucionRound1)
    


def menu():
    op = -1
    while (op != 0):
        print("\n\n   *************************************" + 
              "\n      MENÚ PRINCIPAL: PAKE MULTIPARTE" +
              "\n   *************************************")
        print("\n\t1 - Ejecución con 3 participantes")
        print("\t2 - Ejecución con otro número de participantes")
        print("\t0 - Salir")
        
        
        op = -1
        while ((op < 0) or (op > 2)):
            print("\nIntroduzca el número de la opción que desea realizar:")
            op = int(input())
            
            if ((op < 0) or (op > 2)):
                print("ERROR. Debe introducir el número correspondiente a una de las opciones disponibles.")

        
        if op == 1: # ejemplo 3 participantes
            ejemplo_3_usuarios()

        
        elif op == 2: # introducir num participantes
            print("\nIntroduzca el número de participantes:")
            numParticipantes = int(input())
            ejemplo_n_usuarios(numParticipantes)



if __name__ == "__main__":
    menu()


    
