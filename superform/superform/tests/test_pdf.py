# coding=utf-8
import json
from superform import Publishing
from superform.plugins import pdf


def test_run_PDF():
    pub = Publishing()
    pub.title = 'test-Title'
    pub.description = "Very long test : Le mot « wiki » signifie, en hawaïen, rapide2, vite3 ou informel4. Il a été choisi par Ward Cunningham lorsqu'il créa le premier wiki, qu'il appela WikiWikiWeb. Il utilisa l'expression « wiki wiki », un redoublement qui signifie « très rapide », « très vite »5, car c'est le premier terme hawaïen qu'il apprit lorsqu'il dut prendre un bus à la sortie de l'aéroport, et qu'à la création de son site, il voulait un terme amusant pour dire rapide. Dans l'URL du site, apparaissait uniquement le terme « wiki », ce qui a probablement poussé les visiteurs à l'appeler ainsi5. Pour l'OQLF le terme « wiki » est donc un nom commun qui s'accorde au pluriel6. Le journal The Economist fait remarquer que le mot wiki peut être lu comme l'acronyme de « What I Know Is » (littéralement : « ce que je sais est » ou « voici ce que je sais »)7. Le concours de création littéraire et artistique Dis-moi dix mots a sélectionné le mot « wiki » pour son édition de 2014-20158 et en donne une définition."
    config_channel = json.dumps({'Logo': "UCL", 'Format': "A4"})
    run_result = pdf.run(pub, config_channel, True)
    assert (run_result[0] == "status_OK")  # pdf was generated
    fileName = run_result[1]
    fileSize = run_result[2]
    fileNameWithoutDot = fileName[:-4]
    fileNameWithoutDotWithoutFormatWithoutLogo = fileNameWithoutDot[
                                                 fileNameWithoutDot.find(
                                                     "-") + 4:]
    assert (
        fileNameWithoutDotWithoutFormatWithoutLogo.isalnum())  # pdf name contains no special char
    assert (fileName.startswith("UCL-A4"))  # it used UCL logo and A4 format
    assert (fileSize > 0)  # verify that the pdf size is bigger than 0
