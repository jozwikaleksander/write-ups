let imgs;
let wrapper;
let wrapperImage;

const createFullscreenWrapper = () => {
    wrapper = document.createElement('div');
    wrapper.onclick = closeAnImage;
    wrapper.classList.add("fullscreenWrapper");
    wrapperImage = document.createElement('img');
    wrapperImage.classList = 'fullscreenImage';
    wrapper.appendChild(wrapperImage);
    document.body.appendChild(wrapper);
}

const findImages = () => {
    imgs = document.querySelectorAll('img');

    // Filtering images to only those which do not have classes
    let imgsFiltered = []
    imgs.forEach((img) => {
        if(img.classList.length == 0){
            img.classList.add('zoomable');
            imgsFiltered.push(img);
            img.onclick = previewImage;
        }
    })
}

// Image preview func
const previewImage = (e) => {
    const img = e.target;
    
    if(img.classList.contains('zoomable')){
        wrapper.classList.add('visible');
        wrapperImage.src = img.src;
    }
    console.log(img);
}

// Func for closing an image
const closeAnImage = (e) => {
    console.log('visible');
    if(wrapper.classList.contains('visible')){
        wrapper.classList.remove('visible');
    }
}

$(document).ready(() =>  {
    createFullscreenWrapper();
    findImages();
})