/*analysis*/
//base
var base = document.querySelectorAll("#basic-info tr");
var baseO = {
    'sha256': base[0].children[1].innerHTML.trim(),
    'filename': base[0].children[1].innerHTML.trim()
};
//scan
var scan = document.querySelectorAll("#antivirus-results tbody tr");
var scanO = {};
scan.forEach(function(v) {
    scanO[v.children[0].textContent.trim()] = v.children[1].textContent.trim();
});
/*file detail*/
var fileDetail = document.querySelectorAll("#file-details .enum-container");
var h5s = document.querySelectorAll("#file-details>h5");
var h5c = [];
h5s.forEach(function(v) {
    h5c.push(v.textContent.trim());
});
// PE sections
for (var i = 0; i < h5c.length; i++) {
    if (h5c[i] == "PE sections") {
        var pesectionO = [];
        fileDetail[i].querySelectorAll(".enum").forEach(function(v, j) {
            if (j > 0) {
                pesectionO.push({
                    "Name": v.children[0].innerHTML.trim(),
                    "Virtual_Address": v.children[1].innerHTML.trim(),
                    "Virtual_Size": v.children[2].innerHTML.trim(),
                    "Size_of_Raw_Data": v.children[3].innerHTML.trim(),
                    "Entropy": v.children[4].innerHTML.trim(),
                    "MD5": v.children[5].innerHTML.trim()
                });
            }
        });
        break;
    }
}
// peimport

for (var i = 0; i < h5c.length; i++) {
    if (h5c[i] == "PE imports") {
        var peimportO = {};
        fileDetail[i].querySelectorAll(".expand-canvas").forEach(function(v) {
            var arr = [];
            v.querySelectorAll(".hide > .enum").forEach(function(v2) {
                arr.push("xxxx " + v2.innerHTML.trim());
            });
            peimportO[v.querySelector("a").innerHTML.trim().substr(4)] = arr.join(",");
        });
        break;
    }
}
/*addinfo*/
var addinfo = document.querySelectorAll("#additional-info-content .enum-container");
// File identification
var fileIdentO = {};
addinfo[0].querySelectorAll(".enum").forEach(function(v) {
    if (v.querySelector("table")) {
        var name = v.querySelector("td.field-key").innerHTML.trim();
        var val = v.querySelector("td.field-value").textContent.trim().split("\n      \n");
        var arr = [];
        val.forEach(function(v2) {
            arr.push(v2.trim());
        });
        fileIdentO[name] = arr;
    } else {
        var name = v.childNodes[1].textContent.trim();
        if (name == "ssdeep" || name == "Magic literal") {
            fileIdentO[name] = v.children[1].innerHTML.trim();
        } else if (name == "Tags") {
            var arr = [];
            v.querySelectorAll(".label-info").forEach(function(v2) {
                arr.push(v2.innerHTML.trim());
            });
            fileIdentO[name] = arr;
        } else {
            fileIdentO[name] = v.childNodes[2].textContent.trim();
        }
    }
});
//VirusTotal metadata
var virusMetaO = {};
addinfo[1].querySelectorAll(".enum").forEach(function(v) {
    if (v.querySelector("table")) {
        var name = v.querySelector("td.field-key").innerHTML.trim();
        var val = v.querySelector("td.field-value").textContent.trim().split("\n        \n");
        var arr = [];
        val.forEach(function(v2) {
            arr.push(v2.trim());
        });
        virusMetaO[name] = arr;
    } else {
        var name = v.childNodes[1].textContent.trim();
        virusMetaO[name] = v.childNodes[2].textContent.trim();
    }
});
var _fileDetail = {
    "File_Name": baseO['filename'],
    "File_Size": fileIdentO['File size'],
    "File_Type": fileIdentO['File type'],
    "fileTypeVer": "",
    "MD5": fileIdentO['MD5'],
    "SHA1": fileIdentO['SHA1'],
    "SHA256": fileIdentO['SHA256'],
    "SHA512": '',
    "CRC32": "",
    "Ssdeep": fileIdentO['ssdeep'],
    "Yara": "",
    "$dowload": ""
};
var _overView = {
    "hash": baseO['sha256'],
    "analysis": {
        "Category": "",
        "Started": "",
        "Completed": "",
        "Duration": ""
    },
    "FileDetail": _fileDetail,
    "Signatures": [],
    "Summary_Files": [],
    "Summary_Keys": [],
    "Summary_Mutexes": []
};
var _static = {
    "hash": baseO['sha256'],
    "PEimphash": [],
    "sections": pesectionO,
    "resources": [],
    "imports": {},
    "antivirus": scanO
};
console.log(JSON.stringify(_overView) + ",");
console.log(JSON.stringify(_static) + ",");