// ---------------- SECURE LOGIN / REAL EMAIL OTP ----------------
const OTP_TTL = 2 * 60 * 1000;
let challengeId = "";
let otpExpiresAt = 0;
let otpTimerId = null;

const loginScreen = document.getElementById("loginScreen");
const attendanceApp = document.getElementById("attendanceApp");
const studentForm = document.getElementById("studentForm");
const otpPanel = document.getElementById("otpPanel");
const studentNameInput = document.getElementById("studentName");
const rollNumberInput = document.getElementById("rollNumber");
const phoneNumberInput = document.getElementById("phoneNumber");
const emailAddressInput = document.getElementById("emailAddress");
const otpInput = document.getElementById("otpInput");
const otpTimer = document.getElementById("otpTimer");
const loginMessage = document.getElementById("loginMessage");
const verifyButton = document.getElementById("verifyOtp");
const resendButton = document.getElementById("resendOtp");

function setLoginMessage(message, type=""){
  loginMessage.textContent=message;
  loginMessage.className=`login-message ${type}`.trim();
}

function updateOtpTimer(){
  const remaining=Math.max(0,otpExpiresAt-Date.now());
  const seconds=Math.ceil(remaining/1000);

  otpTimer.textContent=`${String(Math.floor(seconds/60)).padStart(2,"0")}:${String(seconds%60).padStart(2,"0")}`;

  if(remaining<=0){
    clearInterval(otpTimerId);
    challengeId="";
    setLoginMessage("The OTP has expired. Please request a new OTP.","error");
    verifyButton.disabled=true;
  }
}

function startOtpTimer(expiresIn=OTP_TTL / 1000){
  otpExpiresAt=Date.now()+expiresIn*1000;

  clearInterval(otpTimerId);

  updateOtpTimer();

  otpTimerId=setInterval(updateOtpTimer,250);

  verifyButton.disabled=false;
}

async function requestOtp(){
  const name=studentNameInput.value.trim();
  const roll=rollNumberInput.value.trim();
  const phone=phoneNumberInput.value.trim();
  const email=emailAddressInput.value.trim();

  if(!name || !roll || !phone || !email){
    setLoginMessage("Enter your name, roll number, phone number and email first.","error");
    return;
  }

  if(!/^[6-9]\d{9}$/.test(phone)){
    setLoginMessage("Enter a valid 10-digit Indian mobile number.","error");
    return;
  }

  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
    setLoginMessage("Enter a valid email address.","error");
    return;
  }

  const button=document.querySelector("#studentForm .login-primary");

  button.disabled=true;
  resendButton.disabled=true;

  setLoginMessage("Sending your OTP to your email...","");

  try{
    const response=await fetch("/api/send-otp",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      credentials:"same-origin",
      body:JSON.stringify({
        name,
        rollNumber:roll,
        phone,
        email
      })
    });

    const result=await response.json().catch(()=>({}));

    if(!response.ok){
      throw new Error(result.error || "Could not send OTP.");
    }

    challengeId=result.challengeId;

    otpPanel.hidden=false;
    otpInput.value="";

    // 2-minute OTP timer
    startOtpTimer(result.expiresIn || OTP_TTL / 1000);

    setLoginMessage(
      result.message || "OTP sent to your email address. Please check your inbox.",
      "success"
    );

    otpInput.focus();

  }catch(error){
    setLoginMessage(
      error.message || "Could not send OTP. Check the server and Resend settings.",
      "error"
    );
  }finally{
    button.disabled=false;

    setTimeout(()=>{
      resendButton.disabled=false;
    },30000);
  }
}

async function verifyOtpWithServer(){
  if(!challengeId){
    setLoginMessage("Request an OTP first.","error");
    return;
  }

  const otp=otpInput.value.trim();

  if(!/^\d{6}$/.test(otp)){
    setLoginMessage("Enter the 6-digit OTP from your email.","error");
    return;
  }

  if(Date.now()>otpExpiresAt){
    setLoginMessage("OTP expired. Request a new OTP.","error");
    return;
  }

  verifyButton.disabled=true;

  setLoginMessage("Verifying OTP...","");

  try{
    const response=await fetch("/api/verify-otp",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      credentials:"same-origin",
      body:JSON.stringify({
        challengeId,
        otp
      })
    });

    const result=await response.json().catch(()=>({}));

    if(!response.ok){
      throw new Error(result.error || "OTP verification failed.");
    }

    clearInterval(otpTimerId);
    challengeId="";

    // The server accepted the OTP and returned the authenticated user.
    // Open the tracker immediately instead of reloading the page.
    // The response also sets the HttpOnly session cookie for future requests.
    if(
      (result.success || result.authenticated) &&
      result.user
    ){
      showLoggedInUser(
        result.user.name,
        result.user.rollNumber,
        result.user.phone,
        result.user.email
      );

      sendAttendanceReport();

      setLoginMessage("Login successful.","success");

    }else{
      throw new Error(
        "OTP was accepted, but the login session response was incomplete."
      );
    }

  }catch(error){
    setLoginMessage(
      error.message || "Incorrect OTP. Please try again.",
      "error"
    );

    verifyButton.disabled=false;
  }
}

function showLoggedInUser(name,roll,phone="",email=""){
  document.getElementById("loggedUserName").textContent=name;
  document.getElementById("loggedUserRoll").textContent=`Roll No: ${roll}`;

  loginScreen.hidden=true;
  attendanceApp.hidden=false;
}

async function sendAttendanceReport(){
  try{
    await fetch("/api/send-report",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      credentials:"same-origin",
      body:JSON.stringify({
        attendance:data
      })
    });

  }catch(error){
    console.warn(
      "Could not send attendance report:",
      error
    );
  }
}

async function restoreServerSession(){
  try{
    const response=await fetch(
      "/api/session",
      {
        credentials:"same-origin"
      }
    );

    if(!response.ok) return false;

    const result=await response.json();

    if(result.authenticated && result.user){
      showLoggedInUser(
        result.user.name,
        result.user.rollNumber,
        result.user.phone
      );

      return true;
    }

  }catch(error){
    console.warn(
      "Could not restore login session:",
      error
    );
  }

  return false;
}

document.getElementById("logoutBtn").onclick=async()=>{
  try{
    await fetch(
      "/api/logout",
      {
        method:"POST",
        credentials:"same-origin"
      }
    );
  }catch(e){}

  location.reload();
};

studentForm.addEventListener("submit",e=>{
  e.preventDefault();
  requestOtp();
});

verifyButton.onclick=verifyOtpWithServer;

resendButton.onclick=requestOtp;

otpInput.addEventListener("input",()=>{
  otpInput.value=otpInput.value
    .replace(/\D/g,"")
    .slice(0,6);
});

otpInput.addEventListener("keydown",e=>{
  if(e.key==="Enter"){
    verifyOtpWithServer();
  }
});

(async()=>{
  const loggedIn=await restoreServerSession();

  if(!loggedIn){
    attendanceApp.hidden=true;
  }
})();


const timetable = {
  1: [
    ["09:15","10:05","Advanced Data Structures and Algorithm Analysis","class",1],
    ["10:05","10:55","Digital Logic Design and Computer Organization","class",1],
    ["10:55","11:45","Discrete Mathematics","class",1],
    ["11:45","12:35","Object Oriented Programming Using Java","class",1]
  ],

  2: [
    ["09:15","10:05","Universal Human Values-II","class",1],
    ["10:05","10:55","Advanced Data Structures and Algorithm Analysis","class",1],
    ["10:55","11:45","Object Oriented Programming Using Java","class",1],
    ["11:45","12:35","Digital Logic Design and Computer Organization","class",1]
  ],

  3: [
    ["09:15","10:55","Digital Logic Design and Computer Organization Lab","lab",2],
    ["10:55","11:45","Digital Logic Design and Computer Organization","class",1],
    ["11:45","12:35","Discrete Mathematics","class",1],
    ["13:30","14:20","Digital Logic Design and Computer Organization","class",1],
    ["14:20","15:10","Object Oriented Programming Using Java","class",1]
  ],

  4: [
    ["10:55","12:35","Full Stack Development","lab",2],
    ["13:30","14:20","Discrete Mathematics","class",1],
    ["14:20","15:10","Digital Logic Design and Computer Organization","class",1]
  ],

  5: [
    ["10:05","10:55","Universal Human Values-II","class",1],
    ["10:55","11:45","Discrete Mathematics","class",1],
    ["11:45","12:35","Object Oriented Programming Using Java","class",1],
    ["13:30","14:20","Advanced Data Structures and Algorithm Analysis","class",1],
    ["14:20","15:10","Discrete Mathematics","class",1],
    ["15:10","16:50","Object Oriented Programming Using Java Lab","lab",2]
  ],

  6: [
    ["10:05","10:55","Advanced Data Structures and Algorithm Analysis","class",1],
    ["10:55","12:35","Advanced Data Structures and Algorithm Analysis Lab","lab",2],
    ["13:30","14:20","Object Oriented Programming Using Java","class",1],
    ["14:20","15:10","Universal Human Values-II","class",1],
    ["15:10","16:00","Advanced Data Structures and Algorithm Analysis","class",1]
  ]
};

const names=[
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday"
];

const STORAGE_KEY = "attendanceData_v2";
const LEGACY_STORAGE_KEY = "attendanceData";

function readAttendance(){
  try{
    const current=JSON.parse(
      localStorage.getItem(STORAGE_KEY) || "null"
    );

    if(current && typeof current==="object"){
      return current;
    }

  }catch(e){
    console.warn(
      "Could not read saved attendance:",
      e
    );
  }

  try{
    const legacy=JSON.parse(
      localStorage.getItem(LEGACY_STORAGE_KEY) || "{}"
    );

    const migrated={};

    Object.entries(legacy || {}).forEach(
      ([date,vals])=>{
        const d=new Date(date+"T00:00:00");

        const items=scheduleForDate
          ? scheduleForDate(d)
          : (timetable[d.getDay()] || []);

        if(!Array.isArray(vals) || !items.length){
          return;
        }

        const out={};

        Object.entries(vals).forEach(
          ([index,status])=>{
            const x=items[Number(index)];

            if(!x || !status) return;

            out[sessionKey(x)]=status;
          }
        );

        if(Object.keys(out).length){
          migrated[date]=out;
        }
      }
    );

    if(Object.keys(migrated).length){
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(migrated)
      );

      return migrated;
    }

  }catch(e){
    console.warn(
      "Could not migrate old attendance:",
      e
    );
  }

  return {};
}

let data={};

let selected=new Date();
selected.setHours(0,0,0,0);

let view=new Date(
  selected.getFullYear(),
  selected.getMonth(),
  1
);

const key=d =>
  `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;

const pad=n =>
  String(n).padStart(2,"0");

const fmt=d =>
  d.toLocaleDateString(
    undefined,
    {
      weekday:"long",
      day:"numeric",
      month:"long",
      year:"numeric"
    }
  );

function sessionKey(x){
  return `${x[0]}-${x[1]}|${x[2]}`
    .replace(/\s+/g," ")
    .trim();
}

function getSavedStatus(d,x,index){
  const day=data[key(d)] || {};

  if(
    Object.prototype.hasOwnProperty.call(
      day,
      sessionKey(x)
    )
  ){
    return day[sessionKey(x)];
  }

  if(
    Object.prototype.hasOwnProperty.call(
      day,
      index
    )
  ){
    return day[index];
  }

  return "";
}

function save(){
  try{
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify(data)
    );

    localStorage.setItem(
      "attendanceLastSaved",
      new Date().toISOString()
    );

    return true;

  }catch(e){
    console.error(
      "Attendance could not be saved:",
      e
    );

    alert(
      "Attendance could not be saved in this browser. Please allow site storage/localStorage and try again."
    );

    return false;
  }
}


// ---------------- REQUESTED DATE SCHEDULES ----------------

const requestedSchedules = {

  1: [
    ["09:15","10:05","Digital Logic Design and Computer Organization","class",1],
    ["10:05","10:55","Discrete Mathematics","class",1],
    ["10:55","11:45","Advanced Data Structures and Algorithm Analysis","class",1],
    ["11:45","12:35","Object Oriented Programming Using Java","class",1]
  ],

  2: [
    ["09:15","10:05","Universal Human Values-II","class",1],
    ["10:05","10:55","Discrete Mathematics","class",1],
    ["10:55","11:45","Object Oriented Programming Using Java","class",1],
    ["11:45","12:35","Digital Logic Design and Computer Organization","class",1]
  ],

  3: [
    ["09:15","10:55","Digital Logic Design and Computer Organization Lab","lab",2],
    ["10:55","11:45","Discrete Mathematics","class",1],
    ["11:45","12:35","Digital Logic Design and Computer Organization","class",1],
    ["13:30","14:20","Advanced Data Structures and Algorithm Analysis","class",1],
    ["14:20","15:10","Object Oriented Programming Using Java","class",1]
  ],

  4: [
    ["10:55","12:35","Full Stack Development","lab",2],
    ["13:30","14:20","Discrete Mathematics","class",1],
    ["14:20","15:10","Digital Logic Design and Computer Organization","class",1],
    ["15:10","16:00","Advanced Data Structures and Algorithm Analysis","class",1]
  ],

  5: [
    ["10:55","11:45","Universal Human Values-II","class",1],
    ["11:45","12:35","Object Oriented Programming Using Java","class",1],
    ["13:30","14:20","Discrete Mathematics","class",1],
    ["14:20","15:10","Advanced Data Structures and Algorithm Analysis","class",1],
    ["15:10","16:50","Object Oriented Programming Using Java Lab","lab",2]
  ],

  6: [
    ["10:05","10:55","Advanced Data Structures and Algorithm Analysis","class",1],
    ["10:55","12:35","Advanced Data Structures and Algorithm Analysis Lab","lab",2],
    ["13:30","14:20","Object Oriented Programming Using Java","class",1],
    ["14:20","15:10","Universal Human Values-II","class",1],
    ["15:10","16:00","Digital Logic Design and Computer Organization","class",1]
  ]
};

const requestedCutoffs = {
  1:"2026-08-31",
  2:"2026-08-25",
  3:"2026-08-19",
  4:"2026-08-20",
  5:"2026-08-21",
  6:"2026-08-22"
};

const requestedStart="2026-07-06";

function scheduleForDate(d){

  const k=key(d);
  const day=d.getDay();

  if(k==="2026-07-03"){
    return requestedSchedules[5];
  }

  if(
    day>=1 &&
    day<=6 &&
    k>=requestedStart &&
    k<=requestedCutoffs[day]
  ){
    return requestedSchedules[day];
  }

  if(
    day===4 &&
    k<="2026-09-03"
  ){
    return [
      ["10:55","12:35","Full Stack Development","lab",2],
      ["13:30","14:20","Discrete Mathematics","class",1],
      ["14:20","15:10","Object Oriented Programming Using Java","class",1],
      ["15:10","16:00","Digital Logic Design and Computer Organization","class",1]
    ];
  }

  if(
    day===6 &&
    k<="2026-08-29"
  ){
    return [
      ["10:05","10:55","Advanced Data Structures and Algorithm Analysis","class",1],
      ["10:55","12:35","Advanced Data Structures and Algorithm Analysis Lab","lab",2],
      ["13:30","14:20","Object Oriented Programming Using Java","class",1],
      ["14:20","15:10","Universal Human Values-II","class",1],
      ["15:10","16:00","Digital Logic Design and Computer Organization","class",1]
    ];
  }

  return timetable[day] || [];
}

data=readAttendance();

function entriesFor(d){
  return scheduleForDate(d);
}

function getDay(d){
  return data[key(d)] || {};
}

function statusFor(d){

  const e=getDay(d);
  const items=entriesFor(d);

  if(!items.length){
    return null;
  }

  const vals=items.map(
    (x,i)=>getSavedStatus(d,x,i)
  );

  if(
    vals.every(
      v=>v==="holiday"
    )
  ){
    return "holiday";
  }

  const active=vals.filter(
    v=>v==="present" ||
       v==="absent"
  );

  if(!active.length){
    return null;
  }

  if(
    active.every(
      v=>v==="present"
    )
  ){
    return "present";
  }

  if(
    active.every(
      v=>v==="absent"
    )
  ){
    return "absent";
  }

  return "mixed";
}

function renderCalendar(){

  const y=view.getFullYear();
  const m=view.getMonth();

  document.getElementById(
    "monthTitle"
  ).textContent=view.toLocaleDateString(
    undefined,
    {
      month:"long",
      year:"numeric"
    }
  );

  const first=new Date(y,m,1);
  const last=new Date(y,m+1,0);

  let html="";

  for(
    let i=0;
    i<first.getDay();
    i++
  ){
    html+='<div class="day empty"></div>';
  }

  for(
    let n=1;
    n<=last.getDate();
    n++
  ){

    const d=new Date(y,m,n);
    const k=key(d);
    const s=statusFor(d);

    const today=
      key(new Date())===k;

    const sel=
      key(selected)===k;

    html+=`
      <div
        class="day ${today?"today ":""}${sel?"selected":""}"
        data-date="${k}"
      >
        <div class="day-number">${n}</div>
        ${
          s
          ? `<div class="day-status ${s}"></div>`
          : ""
        }
      </div>
    `;
  }

  document.getElementById(
    "calendar"
  ).innerHTML=html;

  document
    .querySelectorAll(".day[data-date]")
    .forEach(el=>{
      el.onclick=()=>{
        selected=new Date(
          el.dataset.date+"T00:00:00"
        );

        renderAll();
      };
    });
}

function renderDay(){

  const title=
    document.getElementById(
      "selectedDateTitle"
    );

  const sub=
    document.getElementById(
      "selectedDateSub"
    );

  const box=
    document.getElementById(
      "dayContent"
    );

  title.textContent=fmt(selected);

  const items=entriesFor(selected);

  if(!items.length){

    sub.textContent=
      "No scheduled classes or labs.";

    box.innerHTML=
      '<div class="empty-state">Sunday / no timetable entries.<br>Nothing is counted.</div>';

    return;
  }

  sub.textContent=
    `${items.length} timetable entries • ${items.reduce((a,x)=>a+x[4],0)} attendance periods`;

  box.innerHTML=items.map(
    (x,i)=>{

      const st=
        getSavedStatus(
          selected,
          x,
          i
        );

      return `
        <div class="session">

          <div class="session-main">

            <div>

              <div class="subject">
                ${x[2]}
              </div>

              <div class="time">
                ${time(x[0])} – ${time(x[1])}
                • ${x[4]} period${x[4]>1?"s":""}
              </div>

            </div>

            <span class="badge ${x[3]}">
              ${x[3]==="lab"?"LAB":"CLASS"}
            </span>

          </div>

          <div class="actions">

            <button
              class="${st==="present"?"active present":""}"
              onclick="setStatus(${i},'present')"
            >
              ✓ Present
            </button>

            <button
              class="${st==="absent"?"active absent":""}"
              onclick="setStatus(${i},'absent')"
            >
              ✕ Absent
            </button>

            <button
              class="${st==="holiday"?"active holiday":""}"
              onclick="setStatus(${i},'holiday')"
            >
              ○ Holiday
            </button>

          </div>

        </div>
      `;
    }
  ).join("");
}

function time(t){

  let [h,m]=t
    .split(":")
    .map(Number);

  const ap=h>=12?"PM":"AM";

  h=h%12||12;

  return `${h}:${pad(m)} ${ap}`;
}

function setStatus(i,s){

  const k=key(selected);

  const items=entriesFor(selected);

  const x=items[i];

  if(!x){
    return;
  }

  data[k]??={};

  data[k][sessionKey(x)]=s;

  delete data[k][i];

  if(save()){
    renderAll();
  }
}

document.getElementById(
  "clearDay"
).onclick=()=>{

  delete data[key(selected)];

  save();

  renderAll();
};

document.getElementById(
  "prevMonth"
).onclick=()=>{

  view=new Date(
    view.getFullYear(),
    view.getMonth()-1,
    1
  );

  renderCalendar();
  renderMonthlySummary();
};

document.getElementById(
  "nextMonth"
).onclick=()=>{

  view=new Date(
    view.getFullYear(),
    view.getMonth()+1,
    1
  );

  renderCalendar();
  renderMonthlySummary();
};

document.getElementById(
  "todayBtn"
).onclick=()=>{

  selected=new Date();

  selected.setHours(0,0,0,0);

  view=new Date(
    selected.getFullYear(),
    selected.getMonth(),
    1
  );

  renderAll();
};


function goToDay(offset){

  selected=new Date(
    selected.getFullYear(),
    selected.getMonth(),
    selected.getDate()+offset
  );

  view=new Date(
    selected.getFullYear(),
    selected.getMonth(),
    1
  );

  renderAll();
}

function setAll(status){

  const items=entriesFor(selected);

  if(!items.length){
    return;
  }

  const k=key(selected);

  data[k]??={};

  items.forEach(
    (x,i)=>{
      data[k][sessionKey(x)]=status;
      delete data[k][i];
    }
  );

  if(save()){
    renderAll();
  }
}

document.getElementById(
  "prevDay"
).onclick=()=>goToDay(-1);

document.getElementById(
  "nextDay"
).onclick=()=>goToDay(1);

document.getElementById(
  "allPresent"
).onclick=()=>setAll("present");

document.getElementById(
  "allAbsent"
).onclick=()=>setAll("absent");

document.getElementById(
  "resetData"
).onclick=()=>{

  if(
    confirm(
      "Delete all saved attendance?"
    )
  ){

    data={};

    save();

    renderAll();
  }
};

document.getElementById(
  "targetPct"
).onchange=renderStats;

function renderStats(){

  let present=0;
  let absent=0;
  let holidays=0;

  Object.entries(data).forEach(
    ([k,vals])=>{

      const d=
        new Date(
          k+"T00:00:00"
        );

      const items=
        entriesFor(d);

      items.forEach(
        (x,i)=>{

          const st=
            getSavedStatus(
              d,
              x,
              i
            );

          if(st==="present"){
            present+=x[4];
          }

          if(st==="absent"){
            absent+=x[4];
          }

          if(st==="holiday"){
            holidays+=x[4];
          }
        }
      );
    }
  );

  const conducted=
    present+absent;

  const pct=
    conducted
    ? present/conducted*100
    : 0;

  const target=
    +document.getElementById(
      "targetPct"
    ).value;

  document.getElementById(
    "attendancePct"
  ).textContent=
    conducted
    ? pct.toFixed(2)+"%"
    : "0%";

  document.getElementById(
    "presentCount"
  ).textContent=present;

  document.getElementById(
    "absentCount"
  ).textContent=absent;

  document.getElementById(
    "holidayCount"
  ).textContent=holidays;

  document.getElementById(
    "attendanceSub"
  ).textContent=
    conducted
    ? `${conducted} conducted periods`
    : "No classes recorded";

  document.getElementById(
    "overallPct"
  ).textContent=
    conducted
    ? pct.toFixed(2)+"%"
    : "0%";

  document.getElementById(
    "overallPresent"
  ).textContent=present;

  document.getElementById(
    "overallAbsent"
  ).textContent=absent;

  document.getElementById(
    "overallConducted"
  ).textContent=conducted;

  document.getElementById(
    "overallHolidays"
  ).textContent=holidays;

  renderMonthlySummary();

  renderSubjectAttendance();

  const r=
    document.getElementById(
      "targetResult"
    );

  if(!conducted){

    r.textContent=
      "Record some classes to see your target.";

    r.className="target-result";

    return;
  }

  if(pct>=target){

    const miss=
      Math.floor(
        present/(target/100)
        -present
        -absent
      );

    r.innerHTML=
      `<span class="good">
        You are at ${pct.toFixed(2)}%.
      </span>
      You can miss approximately
      <b>${Math.max(0,miss)}</b>
      more period${miss===1?"":"s"}
      and stay at ${target}%.`;

  }else{

    const need=
      Math.ceil(
        (
          target/100*conducted
          -present
        )
        /(1-target/100)
      );

    r.innerHTML=
      `<span class="warn">
        You are at ${pct.toFixed(2)}%.
      </span>
      Attend the next
      <b>${Math.max(0,need)}</b>
      consecutive periods
      to reach ${target}%.`;
  }
}

function monthlyTotals(year,month){

  let present=0;
  let absent=0;
  let holidays=0;

  const days=
    new Date(
      year,
      month+1,
      0
    ).getDate();

  for(
    let day=1;
    day<=days;
    day++
  ){

    const d=
      new Date(
        year,
        month,
        day
      );

    const items=
      entriesFor(d);

    items.forEach(
      (x,i)=>{

        const st=
          getSavedStatus(
            d,
            x,
            i
          );

        if(st==="present"){
          present+=x[4];
        }
        else if(st==="absent"){
          absent+=x[4];
        }
        else if(st==="holiday"){
          holidays+=x[4];
        }
      }
    );
  }

  const conducted=
    present+absent;

  return {
    present,
    absent,
    holidays,
    conducted,
    pct:
      conducted
      ? present/conducted*100
      : 0
  };
}

function renderMonthlySummary(){

  const y=view.getFullYear();
  const m=view.getMonth();

  const t=
    monthlyTotals(y,m);

  document.getElementById(
    "monthlySummaryLabel"
  ).textContent=
    view.toLocaleDateString(
      undefined,
      {
        month:"long",
        year:"numeric"
      }
    );

  document.getElementById(
    "monthlySummary"
  ).innerHTML=`

    <div class="month-item">
      <b>${t.pct.toFixed(2)}%</b>
      <span>Attendance</span>
    </div>

    <div class="month-item">
      <b>${t.present}</b>
      <span>Present periods</span>
    </div>

    <div class="month-item">
      <b>${t.absent}</b>
      <span>Absent periods</span>
    </div>

    <div class="month-item">
      <b>${t.conducted}</b>
      <span>Conducted periods</span>
    </div>
  `;
}

function renderSubjectAttendance(){

  const totals={};

  Object.entries(data).forEach(
    ([k,vals])=>{

      const d=
        new Date(
          k+"T00:00:00"
        );

      const items=
        entriesFor(d);

      items.forEach(
        (x,i)=>{

          const subject=x[2];

          const st=
            getSavedStatus(
              d,
              x,
              i
            );

          totals[subject]??={
            present:0,
            absent:0,
            conducted:0
          };

          if(st==="present"){
            totals[subject].present+=x[4];
          }
          else if(st==="absent"){
            totals[subject].absent+=x[4];
          }
        }
      );
    }
  );

  const body=
    document.getElementById(
      "subjectAttendanceBody"
    );

  const subjects=
    Object.keys(totals).sort();

  if(!subjects.length){

    body.innerHTML=
      '<tr><td colspan="5" class="subject-empty">Record attendance to see subject-wise percentages.</td></tr>';

    return;
  }

  body.innerHTML=
    subjects.map(
      subject=>{

        const t=
          totals[subject];

        t.conducted=
          t.present+t.absent;

        const pct=
          t.conducted
          ? t.present/t.conducted*100
          : 0;

        return `
          <tr>
            <td>
              <b>${subject}</b>
            </td>

            <td>${t.present}</td>

            <td>${t.absent}</td>

            <td>${t.conducted}</td>

            <td>
              <strong>
                ${pct.toFixed(2)}%
              </strong>
            </td>
          </tr>
        `;
      }
    ).join("");
}

function renderTable(){

  const labels=[
    "",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday"
  ];

  let rows="";

  for(
    let d=1;
    d<=6;
    d++
  ){

    timetable[d].forEach(
      x=>{

        rows+=`
          <tr>
            <td>${labels[d]}</td>
            <td>
              ${time(x[0])} – ${time(x[1])}
            </td>
            <td>${x[2]}</td>
            <td>
              <span class="type ${x[3]}">
                ${x[3]==="lab"?"LAB":"CLASS"}
              </span>
            </td>
            <td>${x[4]}</td>
          </tr>
        `;
      }
    );
  }

  document.getElementById(
    "timetableBody"
  ).innerHTML=rows;
}

function renderAll(){

  renderCalendar();
  renderDay();
  renderStats();
}

renderTable();
renderAll();
