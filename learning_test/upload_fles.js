const{test,expect} = requires('@playwright/test');

test('test file upload', async ({page}) => {

    await page.goto('https://www.interstride.com/')

    await page.getByRole('button', {name: 'Open Chat'}).click();

    const fileInput = await page.getByRole('button', {name: 'Upload Attachments'});
    await fileInput.setInputFile('path/to/your/file.txt')

    expect(await page.getByClass('vis').toBeVisible());
    const filenameValidation= await page.getByRole('link',{name:'file.txt'});

    expect(filenameValidation).toContain('file');


})