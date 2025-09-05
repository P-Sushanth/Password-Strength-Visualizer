const strengthCriteria = {
    length: pwd => pwd.length >= 8,
    uppercase: pwd => /[A-Z]/.test(pwd),
    lowercase: pwd => /[a-z]/.test(pwd),
    number: pwd => /[0-9]/.test(pwd),
    special: pwd => /[^A-Za-z0-9]/.test(pwd)
};

const passwordInput = document.getElementById('passwordInput');
const strengthBar = document.getElementById('strength-fill');
const strengthText = document.getElementById('strength-text');
const pwnedWarning = document.getElementById('pwned-warning');
const toggleBtn = document.getElementById('togglePassword');
const copyBtn = document.getElementById('copyPassword');
const generateBtn = document.getElementById('generatePassword');
const passwordLengthSlider = document.getElementById('passwordLength');
const lengthValue = document.getElementById('lengthValue');

const eyeOpen = toggleBtn.querySelector('.eye-open');
const eyeClosed = toggleBtn.querySelector('.eye-closed');

// Show/Hide with masking
toggleBtn.addEventListener('click', () => {
    passwordInput.classList.toggle('password-hidden');
    if(passwordInput.classList.contains('password-hidden')){
        eyeOpen.style.opacity = 1;
        eyeClosed.style.opacity = 0;
    } else {
        eyeOpen.style.opacity = 0;
        eyeClosed.style.opacity = 1;
    }
});

// Copy password
copyBtn.addEventListener('click', () => {
    passwordInput.select();
    navigator.clipboard.writeText(passwordInput.value)
        .then(()=>alert("Password copied!"))
        .catch(()=>alert("Failed to copy password."));
});

// Slider display
passwordLengthSlider.addEventListener('input', ()=> lengthValue.textContent = passwordLengthSlider.value);

// Generate password
function generateStrongPassword(length=12){
    const lc="abcdefghijklmnopqrstuvwxyz", uc="ABCDEFGHIJKLMNOPQRSTUVWXYZ", num="0123456789", sp="!@#$%^&*()_+-=", all=lc+uc+num+sp;
    let pwd = lc[Math.floor(Math.random()*lc.length)]+uc[Math.floor(Math.random()*uc.length)]+num[Math.floor(Math.random()*num.length)]+sp[Math.floor(Math.random()*sp.length)];
    for(let i=pwd.length;i<length;i++) pwd += all[Math.floor(Math.random()*all.length)];
    return pwd.split('').sort(()=>Math.random()-0.5).join('');
}

generateBtn.addEventListener('click', ()=>{
    const pwd = generateStrongPassword(parseInt(passwordLengthSlider.value));
    passwordInput.value = pwd;
    updateLocalStrength(pwd);
    evaluatePassword();
});

// Repeated pattern check
function hasRepeatedPattern(pwd){ return /(.)\1{2,}/.test(pwd); }

// Reset
function resetPasswordDisplay(){
    strengthBar.className=""; strengthBar.style.width="0";
    strengthText.textContent=""; strengthText.className="";
    pwnedWarning.textContent="";
    Object.keys(strengthCriteria).forEach(k=>{
        const li=document.getElementById(k); li.classList.remove("valid"); li.classList.add("invalid");
    });
}

// Update strength locally
function updateLocalStrength(password){
    if(!password){ resetPasswordDisplay(); return; }
    let score=0; for(let k in strengthCriteria) if(strengthCriteria[k](password)) score++;
    if(hasRepeatedPattern(password)) score=Math.max(1,score-1);
    updateBarAndText(score);
}

// Bar & text update
function updateBarAndText(score){
    strengthBar.className=""; strengthText.className="";
    if(score<=1){ strengthBar.classList.add("weak"); strengthBar.style.width="25%"; strengthText.textContent="Weak"; strengthText.classList.add("weak"); }
    else if(score===2||score===3){ strengthBar.classList.add("medium"); strengthBar.style.width="50%"; strengthText.textContent="Medium"; strengthText.classList.add("medium"); }
    else if(score===4){ strengthBar.classList.add("strong"); strengthBar.style.width="75%"; strengthText.textContent="Strong"; strengthText.classList.add("strong"); }
    else if(score===5){ strengthBar.classList.add("very-strong"); strengthBar.style.width="100%"; strengthText.textContent="Very Strong"; strengthText.classList.add("very-strong"); }
}

// HIBP check
async function isPwnedPassword(password){
    if(!password) return false;
    const msgUint8=new TextEncoder().encode(password);
    const hashBuffer=await crypto.subtle.digest('SHA-1', msgUint8);
    const hashArray=Array.from(new Uint8Array(hashBuffer));
    const hashHex=hashArray.map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
    const prefix=hashHex.slice(0,5), suffix=hashHex.slice(5);
    const response=await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text=await response.text();
    return text.split('\n').some(line=>line.split(':')[0]===suffix);
}

// Evaluate password + update criteria
async function evaluatePassword(){
    const password=passwordInput.value; if(!password){ resetPasswordDisplay(); return; }
    const pwned=await isPwnedPassword(password);
    pwnedWarning.textContent=pwned?"⚠ This password has been exposed in breaches!":"";
    for(let k in strengthCriteria){
        const li=document.getElementById(k);
        if(strengthCriteria[k](password)){ li.classList.remove("invalid"); li.classList.add("valid"); }
        else { li.classList.remove("valid"); li.classList.add("invalid"); }
    }
}

// Debounced input
let debounceTimer;
passwordInput.addEventListener('input', ()=>{
    clearTimeout(debounceTimer);
    if(!passwordInput.value){ resetPasswordDisplay(); return; }
    updateLocalStrength(passwordInput.value);
    debounceTimer=setTimeout(evaluatePassword,300);
});