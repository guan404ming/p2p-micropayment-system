#ifndef AMONGUS_H
#define AMONGUS_H
#include "../fonts.h"

class Amongus : public Fonts
{
    static const int ROWS = 4;
    static const int COLS = 9;

public:
    Amongus() : Fonts(ROWS, COLS) {}

    // Uppercase

    vs A()
    {
        vs character = getCharGrid(4, 8);

        character[0][3] = character[0][4] =
            character[1][3] = character[1][4] =
                character[2][3] = character[2][4] =
                    character[3][1] = character[3][2] = character[3][5] = character[3][6] = '_';
        character[1][2] = character[2][1] = '/';
        character[1][5] = character[2][6] = '\\';
        character[3][0] = character[2][2] = character[3][4] = '(';
        character[2][5] = character[3][3] = character[3][7] = ')';

        return character;
    }

    vs B()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[2][3] =
            character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = '(';
        character[2][1] = ')';
        character[1][5] = '\\';
        character[2][5] = '<';
        character[3][5] = '/';

        return character;
    }

    vs C()
    {
        vs character = getCharGrid(4, 6);

        character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[1][4] =
            character[2][3] = character[2][4] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][5] = character[3][5] = ')';
        character[2][0] = character[2][2] = '(';
        character[1][1] = '/';
        character[3][1] = '\\';

        return character;
    }

    vs D()
    {
        vs character = getCharGrid(4, 7);
        character[0][1] = character[0][4] = character[0][2] = character[0][3] = character[1][3] = character[2][3] =
            character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = character[2][2] = '(';
        character[2][1] = character[2][4] = character[2][6] = ')';
        character[1][5] = '\\';
        character[3][5] = '/';

        // Enter the character grid in ROWS X COLS

        return character;
    }

    vs E()
    {
        vs character = getCharGrid(4, 6);
        character[1][0] = character[3][0] = '(';
        character[1][5] = character[2][1] = character[2][4] = character[3][5] = ')';
        character[1][2] = character[1][3] = character[1][4] = character[2][2] = character[2][3] = character[3][2] = character[3][3] = character[3][4] = character[0][1] = character[0][2] = character[0][3] = character[0][4] = '_';

        return character;
    }

    vs F()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][2] = character[1][3] = character[1][4] = character[2][2] = character[2][3] = character[3][1] = character[3][2] = '_';
        character[1][0] = character[3][0] = '(';
        character[1][5] = character[2][1] = character[2][4] = character[3][3] = ')';
        return character;
    }

    vs G()
    {
        vs character = getCharGrid(4, 6);
        character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[1][4] = character[2][3] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[2][0] = character[2][2] = '(';
        character[1][5] = ')';
        character[1][1] = character[3][5] = '/';
        character[3][1] = '\\';
        character[2][4] = '-';
        character[2][5] = '.';

        // Enter the character grid in ROWS X COLS

        return character;
    }

    vs H()
    {
        vs character = getCharGrid(4, 7);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][5] = character[1][3] = character[2][3] = character[3][1] = character[3][5] = '_';
        character[1][0] = character[1][4] = character[2][5] = character[3][0] = character[3][4] = '(';
        character[1][2] = character[1][6] = character[2][1] = character[3][2] = character[3][6] = ')';
        return character;
    }

    vs I()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][1] = character[1][4] = character[2][1] = character[2][4] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = character[2][3] = '(';
        character[1][5] = character[3][5] = character[2][2] = ')';

        return character;
    }

    vs J()
    {
        vs character = getCharGrid(4, 7);

        // Enter the character grid in ROWS X COLS
        character[0][2] = character[0][3] = character[0][4] = character[0][5] = character[1][2] = character[1][5] = character[2][2] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][1] = character[2][4] = '(';
        character[1][6] = character[2][3] = character[3][5] = ')';
        character[2][0] = '.';
        character[2][1] = '-';
        character[3][0] = '\\';
        return character;
    }

    vs K()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][4] = character[3][1] = character[3][4] = '_';
        character[1][0] = character[2][4] = character[3][0] = '(';
        character[1][2] = character[1][5] = character[2][1] = character[3][2] = character[3][5] = ')';
        character[1][3] = '/';
        character[3][3] = '\\';
        // Enter the character grid in ROWS X COLS

        return character;
    }

    vs L()
    {
        vs character = getCharGrid(4, 6);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][2] = character[2][3] = character[2][4] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[2][2] = character[3][0] = '(';
        character[1][3] = character[2][1] = character[3][5] = ')';
        return character;
    }

    vs M()
    {
        vs character = getCharGrid(4, 8);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][2] = character[0][5] = character[0][6] = character[3][1] = character[3][6] = '_';
        character[1][0] = character[2][6] = character[3][0] = '(';
        character[1][7] = character[2][1] = character[3][7] = ')';
        character[1][3] = character[3][3] = character[3][5] = '\\';
        character[1][4] = character[3][2] = character[3][4] = '/';
        return character;
    }

    vs N()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][4] = character[3][1] = character[3][4] = '_';
        character[1][0] = character[1][3] = character[2][4] = character[3][0] = '(';
        character[1][5] = character[2][1] = character[3][2] = character[3][5] = ')';
        character[1][2] = character[3][3] = '\\';

        // Enter the character grid in ROWS X COLS

        return character;
    }

    vs O()
    {
        vs character = getCharGrid(4, 7);

        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[0][5] =
            character[3][1] = character[3][2] = character[3][3] = character[3][4] = character[3][5] =
                character[1][3] = character[2][3] = '_';
        character[1][0] = character[3][0] = character[2][2] = character[2][5] = '(';
        character[1][6] = character[2][1] = character[2][4] = character[3][6] = ')';
        return character;
    }

    vs P()
    {
        vs character = getCharGrid(4, 6);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[2][2] = character[2][3] = character[2][4] = character[3][1] = character[3][2] = '_';
        character[1][0] = character[3][0] = '(';
        character[2][1] = character[3][3] = ')';
        character[1][5] = '\\';
        character[2][5] = '/';

        return character;
    }

    vs Q()
    {
        vs character = getCharGrid(4, 7);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[0][5] =
            character[3][1] = character[3][2] = character[3][3] = character[1][3] = character[2][3] = '_';
        character[1][0] = character[3][0] = character[2][2] = character[2][5] = '(';
        character[1][6] = character[2][1] = character[2][4] = ')';
        character[3][4] = '/';
        character[3][5] = character[3][6] = '\\';
        return character;
    }

    vs R()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[3][1] = character[3][4] = '_';
        character[1][0] = character[3][0] = '(';
        character[2][1] = character[3][2] = character[3][5] = ')';
        character[3][3] = character[1][5] = '\\';
        character[2][5] = '/';
        return character;
    }

    vs S()
    {
        vs character = getCharGrid(4, 5);

        character[0][1] = character[0][2] = character[0][3] =
            character[1][2] = character[1][3] =
                character[2][1] = character[2][2] =
                    character[3][1] = character[3][2] = character[3][3] = '_';
        character[1][0] = character[3][4] = '/';
        character[1][1] = character[2][3] = ' ';
        character[2][0] = character[2][4] = '\\';
        character[1][4] = ')';
        character[3][0] = '(';

        return character;
    }

    vs T()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] =
            character[1][1] = character[1][4] = character[3][2] = character[3][3] = '_';
        character[1][0] = character[2][3] = character[3][1] = '(';
        character[1][5] = character[2][2] = character[3][4] = ')';
        return character;
    }

    vs U()
    {
        vs character = getCharGrid(4, 8);
        character[0][1] = character[0][2] = character[0][5] = character[0][6] = character[2][3] = character[2][4] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = character[3][5] = character[3][6] = '_';
        character[1][0] = character[1][4] = character[2][2] = character[2][6] = character[3][0] = '(';
        character[1][3] = character[1][7] = character[2][1] = character[2][5] = character[3][7] = ')';

        // Enter the character grid in ROWS X COLS

        return character;
    }

    vs V()
    {
        vs character = getCharGrid(4, 6);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][4] = '_';
        character[1][2] = character[2][1] = character[3][2] = '\\';
        character[1][0] = '(';
        character[1][3] = character[2][4] = character[3][3] = '/';
        character[1][5] = ')';
        return character;
    }

    vs W()
    {
        vs character = getCharGrid(4, 8);
        character[0][1] = character[0][6] = character[3][1] = character[3][2] = character[3][5] = character[3][6] = '_';
        character[1][0] = character[3][0] = '(';
        character[1][7] = character[3][7] = ')';
        character[1][3] = character[1][5] = character[3][3] = '/';
        character[1][2] = character[1][4] = character[3][4] = '\\';
        character[2][1] = ')';
        character[2][6] = '(';
        return character;
    }

    vs X()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][4] = character[3][1] = character[3][4] = '_';
        character[1][0] = character[2][4] = character[3][0] = '(';
        character[1][2] = character[3][3] = '\\';
        character[1][3] = character[3][2] = '/';
        character[1][5] = character[2][1] = character[3][5] = ')';
        return character;
    }

    vs Y()
    {
        vs character = getCharGrid(4, 6);

        // Enter the character grid in ROWS X COLS

        character[0][1] = character[0][4] = character[3][2] = character[3][3] = '_';
        character[1][0] = character[3][1] = '(';
        character[1][5] = character[3][4] = ')';
        character[1][2] = character[2][1] = '\\';
        character[1][3] = character[2][4] = '/';
        return character;
    }

    vs Z()
    {
        vs character = getCharGrid(5, 6);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][1] = character[2][4] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = '(';
        character[1][5] = character[3][5] = ')';
        character[2][1] = character[2][3] = '/';

        return character;
    }

    // Lowercase

    vs a()
    {
        vs character = getCharGrid(4, 8);

        character[0][3] = character[0][4] =
            character[1][3] = character[1][4] =
                character[2][3] = character[2][4] =
                    character[3][1] = character[3][2] = character[3][5] = character[3][6] = '_';
        character[1][2] = character[2][1] = '/';
        character[1][5] = character[2][6] = '\\';
        character[3][0] = character[2][2] = character[3][4] = '(';
        character[2][5] = character[3][3] = character[3][7] = ')';

        return character;
    }

    vs b()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[2][3] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = '(';
        character[2][1] = ')';
        character[1][5] = '\\';
        character[3][5] = '/';
        character[2][5] = '<';
        return character;
    }

    vs c()
    {
        vs character = getCharGrid(4, 6);
        character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[1][4] = character[2][3] = character[2][4] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][1] = '/';
        character[3][1] = '\\';
        character[2][0] = character[2][2] = '(';
        character[1][5] = character[3][5] = ')';
        return character;
    }

    vs d()
    {
        vs character = getCharGrid(4, 7);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[3][4] =
            character[3][1] = character[3][2] = character[3][3] = character[1][3] = character[2][3] = '_';
        character[1][0] = character[3][0] = character[2][2] = '(';
        character[2][1] = character[2][4] = character[2][6] = ')';
        character[3][5] = '/';
        character[1][5] = '\\';
        return character;
    }

    vs e()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][2] = character[1][3] = character[1][4] = character[2][2] = character[2][3] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = '(';
        character[2][1] = character[1][5] = character[2][4] = character[3][5] = ')';
        return character;
    }
    vs f()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][2] = character[1][3] = character[1][4] = character[2][2] = character[2][3] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = '(';
        character[2][1] = character[1][5] = character[2][4] = character[3][5] = ')';
        return character;
    }

    
        vs g()
        {
            vs character = getCharGrid(4,7);

            character[0][2]= character[0][3] = character[0][4]= character[1][3] = character[1][4] = character[2][3] = character[3][2] = character[3][3] =character[3][4] ='_';
            character[1][1] =character[3][5] = '/';
            character[1][5] = ')';
            character[2][0] = character[2][2] = '(';
            character[2][4] = '-';
            character[2][5] = '.';
            character[3][1] = '\\';

            return character;
        }
    

    
    vs h()
    {
        vs character = getCharGrid(4,7);

        //Enter the character grid in ROWS X COLS

        character[0][1] = character[0][5]= character[1][3]= character[2][3]=character[3][5] = character[3][1]='_';
        character[1][0] = character[1][4] =character[3][0] = character[3][4] = character[2][5]='(';
        character[1][6] = character[1][2] = character[3][2] = character[3][6] = character[2][1] = ')';

        return character;
    }

        vs i()
        {
            vs character = getCharGrid(4,6);
            character[0][1]= character[0][2]= character[0][3]= character[0][4]= character[1][1]= character[1][4]= character[2][1]= character[2][4]= character[3][1]= character[3][2]= character[3][3]= character[3][4]='_';
            character[1][0]= character[2][3]= character[3][0]='(';
            character[1][5]= character[2][2]= character[3][5]=')';
            return character;
        }
    

   

    vs j()
    {
        vs character = getCharGrid(4, 7);
        character[0][2] = character[0][3] = character[0][4] = character[0][5] = character[1][2] = character[1][5] = character[2][2] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][1] = character[2][4] = '(';
        character[1][6] = character[2][3] = character[3][5] = ')';
        character[2][0] = '.';
        character[3][0] = '\\';
        return character;
    }

    vs k()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][4] = character[3][1] = character[3][4] = '_';
        character[1][0] = character[2][4] = character[3][0] = '(';
        character[1][2] = character[1][5] = character[2][1] = character[3][2] = character[3][5] = ')';
        character[1][3] = '/';
        character[3][3] = '\\';
        return character;
    }

    vs l()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[2][3] = character[2][4] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[2][2] = character[3][0] = '(';
        character[1][3] = character[2][1] = character[3][5] = ')';
        return character;
    }

    vs m()
    {
        vs character = getCharGrid(4, 8);
        character[0][1] = character[0][2] = character[0][5] = character[0][6] = character[3][1] = character[3][6] = '_';
        character[1][0] = character[2][6] = character[3][0] = '(';
        character[1][7] = character[2][1] = character[3][7] = ')';
        character[1][4] = character[3][2] = character[3][4] = '/';
        character[1][3] = character[3][3] = character[3][5] = '\\';
        return character;
    }

    vs n()
    {
        vs character = getCharGrid(4, 6);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][4] = character[3][1] = character[3][4] = '_';
        character[1][0] = character[1][3] = character[3][0] = character[2][4] = '(';
        character[1][5] = character[2][1] = character[3][2] = character[3][5] = ')';
        character[1][2] = character[3][3] = '\\';
        // character[0][0] = character[0][2] = character[0][3] = character[0][5] = character[1][1] = character[1][4] = character[2][0] =character[2][2] =character[2][3] = character[2][5]  = ' ';

        return character;
    }

    vs o()
    {
        vs character = getCharGrid(4, 7);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[0][5] = character[1][3] = character[2][3] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = character[3][5] = '_';
        character[1][0] = character[2][2] = character[2][5] = character[3][0] = '(';
        character[1][6] = character[2][1] = character[2][4] = character[3][6] = ')';
        return character;
    }

    vs p()
    {
        vs character = getCharGrid(4, 6);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[2][2] = character[2][3] = character[2][4] = character[3][1] = character[3][2] = '_';
        character[1][5] = '\\';
        character[3][3] = character[2][1] = ')';
        character[1][0] = character[3][0] = '(';
        character[2][5] = '/';

        return character;
    }

    vs q()
    {
        vs character = getCharGrid(4, 7);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[0][5] = character[1][3] = character[3][3] = character[2][3] = character[3][1] = character[3][2] = '_';
        character[3][5] = character[3][6] = '\\';
        character[1][6] = character[2][1] = character[2][4] = ')';
        character[1][0] = character[2][2] = character[2][5] = character[3][0] = '(';
        character[3][4] = '/';

        return character;
    }

    vs r()
    {
        vs character = getCharGrid(4, 6);

        // Enter the character grid in ROWS X COLS
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][3] = character[3][1] = character[3][4] = '_';
        character[1][5] = character[3][3] = '\\';
        character[3][5] = character[2][1] = character[3][2] = ')';
        character[1][0] = character[3][0] = '(';
        character[2][5] = '/';

        return character;
    }

    vs s()
    {
        vs character = getCharGrid(4, 5);
        character[0][1] = character[0][2] = character[0][3] = character[1][2] = character[1][3] = character[2][1] = character[2][2] = character[3][1] = character[3][2] = character[3][3] = '_';
        character[1][0] = character[3][4] = '/';
        character[2][0] = character[2][4] = '\\';
        character[1][4] = ')';
        character[3][0] = '(';
        return character;
    }

    vs t()
    {
        vs character = getCharGrid(4,6);

        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][1] = character[1][4] = character[3][2] = character[3][3] ='_';
        character[1][0] = character[2][3] = character[3][1] = '(';
        character[1][5] = character[2][2] = character[3][4] = ')';
        

        return character;
    }

    vs u()
        {
            vs character = getCharGrid(4,8);

            character[0][1] = character[0][2] = character[0][5] = character[0][6] = character[2][3] = character[2][4] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = character[3][5] = character[3][6] = '_';
            character[1][0] = character[1][4] = character[2][2] = character[2][6] = character[3][0] = '(';
            character[1][3] = character[1][7] = character[2][1] = character[2][5] = character[3][7] = ')';
            return character;
        }

    vs v()
        {
            vs character = getCharGrid(4,6);

            character[0][1] = character[0][4] = '_';
            character[1][0] = '(';
            character[1][5] = ')';
            character[1][2] = character[2][1] = character[3][2] = '\\';
            character[1][3] = character[2][4] = character[3][3] = '/';
            return character;
        }


  vs w()
        {
            vs character = getCharGrid(4,8);

            character[0][1] = character[0][6] = character[3][1] = character[3][2] = character[3][5] = character[3][6] = '_';
            character[1][0] = character[2][6] = character[3][0] = '(';
            character[1][7] = character[2][1] = character[3][7] = ')';
            character[1][2] = character[1][4] = character[3][4] = '\\';
            character[1][3] = character[1][5] = character[3][3] = '/';
            return character;
        }
    vs x()
    {
        vs character = getCharGrid(4, 6);

        character[0][1] = character[0][4] = character[3][1] = character[3][4] = '_';
        character[1][0] = character[3][0] = character[2][4] = '(';
        character[1][5] = character[3][5] = character[2][1] = ')';
        character[1][2] = character[3][3] = '\\';
        character[1][3] = character[3][2] = '/';

        return character;
    }


    vs y()
    {
        vs character = getCharGrid(4,6);

        character[0][1] = character[0][4] = character[3][2] = character[3][3] = '_';
        character[1][0] = character[3][1] = '(';
        character[1][5] = character[3][4] = ')';
        character[1][2] = character[2][1] = '\\';
        character[1][3] = character[2][4] = '/';

        return character;
    }



    vs z()
    {
        vs character = getCharGrid(ROWS, COLS);
        character[0][1] = character[0][2] = character[0][3] = character[0][4] = character[1][1] = character[2][4] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = '(';
        character[2][1] = character[2][3] = '/';
        character[1][5] = character[3][5] = ')';
        return character;
    }

    // Numbers

    vs zero()
    {
        vs character = getCharGrid(4, 7);
        character[0][2] = character[0][3] = character[0][4] = character[3][2] = character[3][3] =
            character[3][4] = character[1][3] = character[2][3] = '_';
        character[1][1] = character[3][5] = '/';
        character[1][5] = character[3][1] = '\\';
        character[2][0] = character[2][2] = '(';
        character[2][4] = character[2][6] = ')';

        return character;
    }
    vs one()
    {
        vs character = getCharGrid(4, 4);

        character[0][1] = character[0][2] = character[3][1] = character[3][2] = '_';
        character[1][0] = '/';
        character[1][3] = character[2][1] = character[3][3] = ')';
        character[2][2] = character[3][0] = '(';
        return character;
    }

    vs two()
    {
        vs character = getCharGrid(4, 6);
        character[0][1] = character[0][2] = character[0][3] = character[1][1] = character[1][2] = character[2][3] = character[3][1] = character[3][2] = character[3][3] = character[3][4] = '_';
        character[1][0] = character[3][0] = '(';
        character[2][1] = character[2][4] = '/';
        character[1][4] = '\\';
        character[3][5] = ')';

        return character;
    }

    vs three()
    {
        vs character = getCharGrid(4, 5);
        character[0][1] = character[0][2] = character[0][3] = character[1][1] = character[1][2] = character[2][2] = character[3][1] = character[3][2] = character[3][3] = '_';
        character[1][0] = character[3][0] = character[2][1] = '(';
        character[3][4] = '/';
        character[2][4] = '\\';
        character[1][4] = ')';
        return character;
    }

    vs four()
    {
        vs character = getCharGrid(4, 6);
        character[0][2] = character[0][3] = character[2][4] = character[2][1] = character[3][3] = '_';
        character[2][0] = character[3][2] = '(';
        character[1][1] = '/';
        character[1][4] = '|';
        character[1][2] = '.';
        character[2][5] = character[3][4] = ')';
        return character;

        return character;
    }

    vs five()
    {
        vs character = getCharGrid(4, 5);
        character[0][1] = character[0][2] = character[0][3] = character[1][2] = character[1][3] = character[2][1] = character[2][2] = character[3][1] = character[3][2] = character[3][3] = '_';
        character[1][0] = character[2][0] = '|';
        character[1][4] = ')';
        character[3][0] = '(';
        character[2][4] = '\\';
        character[3][4] = '/';
        return character;
    }

    vs six()
    {
        vs character = getCharGrid(ROWS, COLS);

        // Enter the character grid in ROWS X COLS
        character[0][2] = character[2][2] = '_';
        character[1][1] = character[2][0] = character[3][4] = '/';
        character[3][0] = character[2][4] = '\\';
        character[1][3] = ')';
        character[3][1] = character[3][2] = character[3][3] = '_';

        return character;
    }

    vs seven()
    {
        vs character = getCharGrid(4, 5);

        character[0][1] = character[0][2] = character[0][3] = character[1][1] = character[1][2] = character[3][1] = '_';
        character[2][1] = character[2][3] = character[3][2] = '/';
        character[1][0] = character[3][0] = '(';
        character[1][4] = ')';
        return character;
    }

    vs eight()
    {
        vs character = getCharGrid(4, 5);
        character[0][1] = character[0][2] = character[0][3] = character[1][2] = character[2][2] =
            character[3][1] = character[3][2] = character[3][3] = '_';
        character[2][0] = character[3][4] = '/';
        character[2][4] = character[3][0] = '\\';
        character[1][0] = '(';
        character[1][4] = ')';

        return character;
    }


        vs nine()
        {
            vs character = getCharGrid(4,5);
            character[0][1] = character[0][2] = character[0][3] =  character[1][2] =  character[2][1] =  character[3][2] = '_';
            character[1][0] = character[2][4] =  character[3][3] = '/';
             character[1][4] =  character[2][0] = '\\';
              character[3][1] = '(';

           
            return character;
        }


};
#endif