// Appending small clipboard buttons to code blocks.
const appendCopyButtons = () => {
    const codeBlocks = document.querySelectorAll("pre");

    codeBlocks.forEach((elem) => {
        const clipboardButton = document.createElement("span");
        clipboardButton.className = "clipboard-btn";
        clipboardButton.innerHTML = "<i class='fas fa-clipboard'></i>";
        clipboardButton.onclick = copyToClipboard;
        elem.appendChild(clipboardButton);
    });
}

// Copying code block content to clipboard.
async function copyToClipboard(e) {
    let pre = e.target.closest("pre");
    let code = pre.querySelector("code");
    let text = code.innerText;

    await navigator.clipboard.writeText(text);

    let btn = pre.querySelector("span.clipboard-btn");

    // visual feedback that task is completed
    btn.innerHTML = '<i class="fa-solid fa-clipboard-check"></i>';
    btn.classList.add('activated');

    setTimeout(() => {
        btn.innerHTML = '<i class="fas fa-clipboard"></i>';
        btn.classList.remove('activated');
    }, 700);
}

$(document).ready(() =>  {
    appendCopyButtons();
})