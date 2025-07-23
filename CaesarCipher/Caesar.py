import React, { useState, useEffect } from 'react';

const CaesarCipher = () => {
  const [plaintext, setPlaintext] = useState("Hello, World! This is a secret message.");
  const [shift, setShift] = useState(3);
  const [encrypted, setEncrypted] = useState("");
  const [bruteForcedResults, setBruteForcedResults] = useState([]);
  const [showAllResults, setShowAllResults] = useState(false);
  
  // Caesar encryption function
  function caesarEncrypt(text, shiftAmount) {
    let result = "";
    shiftAmount = shiftAmount % 26;
    for (let char of text) {
      if ('A' <= char && char <= 'Z') {
        let shiftedCharCode = (char.charCodeAt(0) - 'A'.charCodeAt(0) + shiftAmount) % 26 + 'A'.charCodeAt(0);
        result += String.fromCharCode(shiftedCharCode);
      }
      else if ('a' <= char && char <= 'z') {
        let shiftedCharCode = (char.charCodeAt(0) - 'a'.charCodeAt(0) + shiftAmount) % 26 + 'a'.charCodeAt(0);
        result += String.fromCharCode(shiftedCharCode);
      }
      else {
        result += char;
      }
    }
    return result;
  }

  // Brute force decryption
  function caesarDecryptBruteForce(ciphertext) {
    let possibleDecryptions = [];

    for (let shiftAttempt = 1; shiftAttempt < 26; shiftAttempt++) {

      let decryptedText = caesarEncrypt(ciphertext, 26 - shiftAttempt);
      possibleDecryptions.push({ shift: shiftAttempt, text: decryptedText });
    }
    return possibleDecryptions;
  }

  useEffect(() => {
    const encryptedText = caesarEncrypt(plaintext, shift);
    setEncrypted(encryptedText);
    
    // Brute force on encrypted text
    const bruteForceResults = caesarDecryptBruteForce(encryptedText);
    setBruteForcedResults(bruteForceResults);
  }, [plaintext, shift]);

  const edgeCases = [
    { name: "Non-English Characters", text: "Hello, Привет" },
    { name: "Numbers and Symbols", text: "Password123!@#" },
    { name: "Empty String", text: "" },
    { name: "Very Large Shift", text: "Test", shift: 1000 },
    { name: "Negative Shift", text: "Test", shift: -7 },
  ];

  const testEdgeCase = (test) => {
    setPlaintext(test.text);
    if (test.shift !== undefined) {
      setShift(test.shift);
    } else {
      setShift(3); // Default shift
    }
  };

  return (
    <div className="p-4 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-4">Interactive Caesar Cipher <span className="text-lg font-normal">by @ciphermalware</span></h1>
      
      <div className="mb-6 bg-gray-100 p-4 rounded-lg">
        <h2 className="font-bold mb-2">Encryption</h2>
        <div className="mb-4">
          <label className="block mb-1">Plaintext:</label>
          <textarea 
            className="w-full p-2 border rounded"
            rows="3"
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
          />
        </div>
        
        <div className="mb-4">
          <label className="block mb-1">Shift Value:</label>
          <div className="flex items-center">
            <input 
              type="range" 
              min="-25" 
              max="25" 
              value={shift}
              onChange={(e) => setShift(parseInt(e.target.value))}
              className="mr-2"
            />
            <input 
              type="number" 
              value={shift}
              onChange={(e) => setShift(parseInt(e.target.value))}
              className="w-16 p-1 border rounded"
            />
          </div>
        </div>
        
        <div className="mb-4">
          <label className="block mb-1">Encrypted Result:</label>
          <div className="p-2 bg-white border rounded">{encrypted}</div>
        </div>
      </div>
      
      <div className="mb-6 bg-gray-100 p-4 rounded-lg">
        <h2 className="font-bold mb-2">Decryption</h2>
        <div className="mb-4">
          <label className="block mb-1">Decrypted with Known Key (shift {shift}):</label>
          <div className="p-2 bg-white border rounded">{caesarEncrypt(encrypted, -shift)}</div>
        </div>
        
        <div>
          <h3 className="font-semibold mb-1">Brute Force Results:</h3>
          <button 
            className="mb-2 px-2 py-1 bg-blue-500 text-white rounded"
            onClick={() => setShowAllResults(!showAllResults)}
          >
            {showAllResults ? "Hide Results" : "Show All Results"}
          </button>
          
          {showAllResults && (
            <div className="max-h-64 overflow-y-auto border rounded p-2 bg-white">
              {bruteForcedResults.map((result) => (
                <div 
                  key={result.shift} 
                  className={`mb-1 p-1 ${result.text === plaintext ? 'bg-green-100' : ''}`}
                >
                  <span className="font-mono">Shift {result.shift.toString().padStart(2, ' ')}: </span>
                  {result.text}
                  {result.text === plaintext && <span className="ml-2 text-green-600 font-bold"> ← Original</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      
      <div className="bg-gray-100 p-4 rounded-lg">
        <h2 className="font-bold mb-3">Test Edge Cases</h2>
        <div className="grid grid-cols-2 gap-2">
          {edgeCases.map((test, index) => (
            <button 
              key={index}
              className="p-2 bg-blue-500 text-white rounded"
              onClick={() => testEdgeCase(test)}
            >
              {test.name}
              {test.shift !== undefined && ` (shift=${test.shift})`}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default CaesarCipher;
